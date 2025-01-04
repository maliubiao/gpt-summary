Response:
The user is asking for an analysis of the C++ source code file `blink/renderer/core/layout/shapes/shape.cc`. I need to identify its purpose, its relationship to web technologies like JavaScript, HTML, and CSS, and provide examples of its usage and potential errors.

**Plan:**

1. **Identify the Core Functionality:** The file deals with the concept of "shapes" in the Blink rendering engine. This likely relates to CSS properties like `shape-outside` and potentially other shape-related features.
2. **Break Down Key Functions:** Analyze the main functions within the `Shape` class and its related helper functions. Focus on how different types of shapes are created (circle, ellipse, polygon, inset, raster).
3. **Connect to Web Technologies:**  Explain how these shape representations in C++ are used to implement CSS shape properties, influencing the layout of HTML elements.
4. **Illustrate with Examples:**  Provide HTML and CSS examples demonstrating how these shapes are used to achieve specific visual layouts.
5. **Consider User/Programming Errors:** Think about common mistakes developers might make when using shape-related CSS properties that would be handled by this code.
6. **Address Logic and I/O (Where Applicable):** While not strictly input/output in a user-facing sense, consider the "inputs" to the shape creation functions (e.g., CSS values) and the "outputs" (shape objects used in layout).
这个 C++ 源代码文件 `blink/renderer/core/layout/shapes/shape.cc` 的主要功能是**创建和管理各种形状 (Shape) 对象**，这些形状对象用于定义网页元素内容周围的非矩形布局区域。

**功能详细列举:**

1. **定义抽象基类 `Shape`:**  `Shape` 类本身是一个抽象基类，定义了所有具体形状类型的通用接口。它包含以下成员：
    *   `writing_mode_`:  存储形状相关的书写模式（例如，水平从左到右，垂直从上到下）。
    *   `margin_`: 存储形状的外边距。

2. **创建不同类型的形状:**  该文件提供了静态工厂方法 `CreateShape`，用于根据 `BasicShape` 对象（通常来自 CSS 的 `shape-outside` 属性）创建不同类型的具体形状：
    *   **圆形 (`BasicShapeCircle`):**  根据圆心坐标和半径创建 `EllipseShape` 对象，表示一个圆形。
    *   **椭圆 (`BasicShapeEllipse`):** 根据中心坐标和两个半径创建 `EllipseShape` 对象，表示一个椭圆。
    *   **多边形 (`BasicShapePolygon`):**  根据一系列顶点坐标创建 `PolygonShape` 对象，表示一个多边形。
    *   **内凹矩形 (`BasicShapeInset`):** 根据内边距值和圆角半径创建 `BoxShape` 对象，表示一个带有圆角的矩形。

3. **创建基于图像的形状 (`RasterShape`):**  该文件还提供了 `CreateRasterShape` 方法，用于根据提供的图像（例如 PNG 或 SVG）创建一个形状。它会扫描图像的 alpha 通道，根据阈值来确定哪些像素属于形状的内部。
    *   `ExtractImageData`:  从 `Image` 对象中提取像素数据。
    *   `ExtractIntervalsFromImageData`:  根据提取的像素数据和指定的阈值，计算出每一行中形状的水平间隔。

4. **创建布局盒子的形状 (`CreateLayoutBoxShape`):**  根据 `FloatRoundedRect` 对象创建一个 `BoxShape`，通常用于处理元素自身的形状（例如，带有 `border-radius` 的元素）。

5. **创建空的栅格形状 (`CreateEmptyRasterShape`):** 创建一个没有实际形状数据的 `RasterShape` 对象，通常用于处理错误情况或初始状态。

**与 JavaScript, HTML, CSS 的关系:**

`shape.cc` 文件中的代码是 Blink 渲染引擎的一部分，它直接参与了 CSS `shape-outside` 属性的实现。

*   **CSS:** CSS 的 `shape-outside` 属性允许开发者定义一个元素的浮动区域不是简单的矩形，而是基于几何形状或图像的。`shape.cc` 中的代码负责解析 CSS 中定义的形状值（例如 `circle()`, `ellipse()`, `polygon()`, `inset()`, `url()`），并创建相应的 `Shape` 对象。

    **例子：**

    ```html
    <div style="width: 200px; height: 200px; float: left; shape-outside: circle(50%);">
      This text will wrap around the circle.
    </div>
    <p>Some more text here.</p>
    ```

    在这个例子中，CSS 属性 `shape-outside: circle(50%);` 会被 Blink 引擎解析，最终在 `shape.cc` 中创建一个表示圆形的 `EllipseShape` 对象。这个形状对象会影响浮动元素周围文本的布局方式。

    ```html
    <div style="width: 200px; height: 200px; float: left; shape-outside: url(image.png);">
      This text will wrap around the non-transparent areas of the image.
    </div>
    <p>Some more text here.</p>
    ```

    在这个例子中，`shape-outside: url(image.png);` 会导致 `shape.cc` 中的 `CreateRasterShape` 方法被调用，根据 `image.png` 的 alpha 通道创建一个 `RasterShape` 对象。

*   **HTML:** HTML 定义了网页的结构，而 CSS 负责样式。`shape-outside` 属性是应用于 HTML 元素的 CSS 属性。

*   **JavaScript:** JavaScript 可以通过 DOM API 修改元素的样式，包括 `shape-outside` 属性。当 JavaScript 修改 `shape-outside` 属性时，Blink 引擎会重新解析该属性并可能创建新的 `Shape` 对象。

    **例子：**

    ```javascript
    const element = document.querySelector('div');
    element.style.shapeOutside = 'polygon(50% 0%, 100% 50%, 50% 100%, 0% 50%)';
    ```

    这段 JavaScript 代码会动态地改变一个 `div` 元素的 `shape-outside` 属性，导致 Blink 引擎重新计算形状。

**逻辑推理的假设输入与输出:**

假设输入一个 `BasicShapeInset` 对象，表示一个带有圆角的内凹矩形，其 CSS 定义如下：

```css
shape-outside: inset(10px 20px 30px 40px round 5px 10px 15px 20px);
```

并且假设该元素自身的尺寸是 `width: 300px; height: 200px;`。

**假设输入:**

*   `basic_shape`: 指向 `BasicShapeInset` 对象的指针，该对象包含了 `top: 10px`, `right: 20px`, `bottom: 30px`, `left: 40px` 以及各个角的圆角半径。
*   `logical_box_size`:  `LogicalSize(300, 200)`，表示元素的逻辑尺寸。
*   `writing_mode`:  例如 `WritingMode::kHorizontalTb` (水平从左到右)。
*   `margin`: 例如 `0`。

**逻辑推理:**

1. `CreateShape` 函数会被调用，参数包含上述输入。
2. 根据 `basic_shape->GetType()` 判断是 `BasicShape::kBasicShapeInsetType`。
3. 计算各个边的内边距的像素值：`left = 40px`, `top = 10px`, `right = 20px`, `bottom = 30px`。
4. 计算内凹矩形的初始矩形范围：`gfx::RectF(40, 10, max(300 - 40 - 20, 0), max(200 - 10 - 30, 0))`，即 `gfx::RectF(40, 10, 240, 160)`。
5. 计算各个角的圆角半径的像素值，并转换为 `gfx::SizeF` 对象。
6. 创建一个 `FloatRoundedRect` 对象，包含矩形范围和圆角半径信息。
7. 调用 `CreateInsetShape` 函数，该函数会创建一个 `BoxShape` 对象，该对象内部存储了表示内凹矩形的 `FloatRoundedRect` 信息。

**假设输出:**

返回一个指向 `BoxShape` 对象的 `std::unique_ptr<Shape>`，该 `BoxShape` 对象描述了一个左上角起始于 `(40, 10)`，尺寸为 `240x160`，并且具有指定的圆角半径的矩形形状。

**用户或编程常见的使用错误举例:**

1. **无效的 `shape-outside` 值:** 用户可能会在 CSS 中提供无效的 `shape-outside` 值，例如拼写错误或语法错误。这会导致 Blink 引擎无法解析该值，可能不会创建任何形状，或者回退到默认的矩形形状。

    **例子：** `shape-outside: circl(50%);` (拼写错误)。

2. **图像 URL 错误:**  如果 `shape-outside` 使用 `url()` 引用图像，但该 URL 指向一个不存在的图像或者加载失败的图像，`CreateRasterShape` 将无法提取图像数据，最终可能创建一个空的 `RasterShape`。

    **例子：** `shape-outside: url(nonexistent.png);`

3. **阈值设置不当 (对于 `image()`):**  当使用 `shape-outside: image()` 时，提供的阈值可能会导致意外的结果。如果阈值过高，可能会将图像中几乎所有像素都视为透明，导致形状消失。如果阈值过低，可能会将图像中几乎所有像素都视为不透明，导致形状接近图像的原始边界。

    **例子：** `shape-outside: image(url(image.png), 0.99);` (极高的阈值)。

4. **`clip-path` 和 `shape-outside` 的混淆:**  开发者可能会混淆 `clip-path` 和 `shape-outside`。`clip-path` 用于裁剪元素自身的内容，而 `shape-outside` 用于定义元素浮动时的形状。使用错误的属性会导致布局或裁剪上的错误。

5. **性能问题:** 对于复杂的 `polygon()` 或基于大尺寸图像的 `image()` 形状，在布局过程中计算形状可能会消耗较多的资源，尤其是在频繁的页面重排或滚动时。开发者需要注意避免创建过于复杂的形状。

这些错误通常会在浏览器的开发者工具中显示警告或错误信息，帮助开发者进行调试。

Prompt: 
```
这是目录为blink/renderer/core/layout/shapes/shape.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 2012 Adobe Systems Incorporated. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials
 *    provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/layout/shapes/shape.h"

#include <algorithm>
#include <memory>
#include <utility>

#include "cc/paint/paint_flags.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/core/layout/geometry/logical_size.h"
#include "third_party/blink/renderer/core/layout/geometry/writing_mode_converter.h"
#include "third_party/blink/renderer/core/layout/shapes/box_shape.h"
#include "third_party/blink/renderer/core/layout/shapes/ellipse_shape.h"
#include "third_party/blink/renderer/core/layout/shapes/polygon_shape.h"
#include "third_party/blink/renderer/core/layout/shapes/raster_shape.h"
#include "third_party/blink/renderer/core/svg/graphics/svg_image.h"
#include "third_party/blink/renderer/core/typed_arrays/array_buffer/array_buffer_contents.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_typed_array.h"
#include "third_party/blink/renderer/platform/geometry/float_rounded_rect.h"
#include "third_party/blink/renderer/platform/geometry/length_functions.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context.h"
#include "third_party/blink/renderer/platform/graphics/graphics_types.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_canvas.h"
#include "third_party/blink/renderer/platform/graphics/static_bitmap_image.h"
#include "third_party/blink/renderer/platform/graphics/unaccelerated_static_bitmap_image.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"
#include "third_party/skia/include/core/SkSurface.h"
#include "ui/gfx/geometry/size_f.h"

namespace blink {

namespace {

// This helps to scan pixel data in a logical direction.
class LogicalPixelScanner {
  STACK_ALLOCATED();

 public:
  // Initialize the instance, and move to the logical origin.
  LogicalPixelScanner(const DOMUint8ClampedArray& pixel_array,
                      const gfx::Size& size,
                      WritingMode writing_mode)
      : pixel_array_(pixel_array), size_(size), writing_mode_(writing_mode) {}

  // Move to the inline-end direction by one pixel.
  void Next() { ++inline_offset_; }

  // Move to the block-end direction by one pixel, and move to the
  // inline-start position.
  void NextLine() {
    ++block_offset_;
    inline_offset_ = 0;
  }

  // Get the alpha channel value of the current pixel.
  uint8_t GetAlpha() const {
    return pixel_array_.Item(PixelOffset() + kAlphaOffsetInPixel);
  }

 private:
  // Each pixel is four bytes: RGBA.
  static constexpr uint32_t kBytesPerPixel = 4;
  static constexpr uint32_t kAlphaOffsetInPixel = 3;

  uint32_t PixelOffset() const {
    uint32_t x, y;
    switch (writing_mode_) {
      case WritingMode::kHorizontalTb:
        x = inline_offset_;
        y = block_offset_;
        break;
      case WritingMode::kVerticalRl:
      case WritingMode::kSidewaysRl:
        x = size_.width() - block_offset_ - 1;
        y = inline_offset_;
        break;
      case WritingMode::kVerticalLr:
        x = block_offset_;
        y = inline_offset_;
        break;
      case WritingMode::kSidewaysLr:
        x = block_offset_;
        y = size_.height() - inline_offset_ - 1;
        break;
    }
    return (y * size_.width() + x) * kBytesPerPixel;
  }

  const DOMUint8ClampedArray& pixel_array_;
  const gfx::Size size_;
  const WritingMode writing_mode_;
  uint32_t inline_offset_ = 0;
  uint32_t block_offset_ = 0;
};

}  // namespace

static std::unique_ptr<Shape> CreateInsetShape(const FloatRoundedRect& bounds) {
  DCHECK_GE(bounds.Rect().width(), 0);
  DCHECK_GE(bounds.Rect().height(), 0);
  return std::make_unique<BoxShape>(bounds);
}

std::unique_ptr<Shape> Shape::CreateShape(const BasicShape* basic_shape,
                                          const LogicalSize& logical_box_size,
                                          WritingMode writing_mode,
                                          float margin) {
  DCHECK(basic_shape);

  WritingModeConverter converter({writing_mode, TextDirection::kLtr},
                                 logical_box_size);
  float box_width = converter.OuterSize().width.ToFloat();
  float box_height = converter.OuterSize().height.ToFloat();
  std::unique_ptr<Shape> shape;

  switch (basic_shape->GetType()) {
    case BasicShape::kBasicShapeCircleType: {
      const BasicShapeCircle* circle = To<BasicShapeCircle>(basic_shape);
      gfx::PointF center =
          PointForCenterCoordinate(circle->CenterX(), circle->CenterY(),
                                   gfx::SizeF(box_width, box_height));
      float radius = circle->FloatValueForRadiusInBox(
          center, gfx::SizeF(box_width, box_height));
      gfx::PointF logical_center = converter.ToLogical(center);

      shape = std::make_unique<EllipseShape>(logical_center, radius, radius);
      break;
    }

    case BasicShape::kBasicShapeEllipseType: {
      const BasicShapeEllipse* ellipse = To<BasicShapeEllipse>(basic_shape);
      gfx::PointF center =
          PointForCenterCoordinate(ellipse->CenterX(), ellipse->CenterY(),
                                   gfx::SizeF(box_width, box_height));
      float radius_x = ellipse->FloatValueForRadiusInBox(ellipse->RadiusX(),
                                                         center.x(), box_width);
      float radius_y = ellipse->FloatValueForRadiusInBox(
          ellipse->RadiusY(), center.y(), box_height);
      gfx::PointF logical_center = converter.ToLogical(center);

      shape = std::make_unique<EllipseShape>(logical_center, radius_x, radius_y,
                                             writing_mode);
      break;
    }

    case BasicShape::kBasicShapePolygonType: {
      const BasicShapePolygon* polygon = To<BasicShapePolygon>(basic_shape);
      const Vector<Length>& values = polygon->Values();
      wtf_size_t values_size = values.size();
      DCHECK(!(values_size % 2));
      Vector<gfx::PointF> vertices(values_size / 2);
      for (wtf_size_t i = 0; i < values_size; i += 2) {
        gfx::PointF vertex(FloatValueForLength(values.at(i), box_width),
                           FloatValueForLength(values.at(i + 1), box_height));
        vertices[i / 2] = converter.ToLogical(vertex);
      }
      shape = std::make_unique<PolygonShape>(std::move(vertices),
                                             polygon->GetWindRule());
      break;
    }

    case BasicShape::kBasicShapeInsetType: {
      const BasicShapeInset& inset = *To<BasicShapeInset>(basic_shape);
      float left = FloatValueForLength(inset.Left(), box_width);
      float top = FloatValueForLength(inset.Top(), box_height);
      float right = FloatValueForLength(inset.Right(), box_width);
      float bottom = FloatValueForLength(inset.Bottom(), box_height);
      gfx::RectF rect(left, top, std::max<float>(box_width - left - right, 0),
                      std::max<float>(box_height - top - bottom, 0));

      gfx::SizeF box_size(box_width, box_height);
      gfx::SizeF top_left_radius =
          SizeForLengthSize(inset.TopLeftRadius(), box_size);
      gfx::SizeF top_right_radius =
          SizeForLengthSize(inset.TopRightRadius(), box_size);
      gfx::SizeF bottom_left_radius =
          SizeForLengthSize(inset.BottomLeftRadius(), box_size);
      gfx::SizeF bottom_right_radius =
          SizeForLengthSize(inset.BottomRightRadius(), box_size);

      FloatRoundedRect physical_rect(rect, top_left_radius, top_right_radius,
                                     bottom_left_radius, bottom_right_radius);
      physical_rect.ConstrainRadii();

      shape = CreateInsetShape(BoxShape::ToLogical(physical_rect, converter));
      break;
    }

    default:
      NOTREACHED();
  }

  shape->writing_mode_ = writing_mode;
  shape->margin_ = margin;

  return shape;
}

std::unique_ptr<Shape> Shape::CreateEmptyRasterShape(WritingMode writing_mode,
                                                     float margin) {
  std::unique_ptr<RasterShapeIntervals> intervals =
      std::make_unique<RasterShapeIntervals>(0, 0);
  std::unique_ptr<RasterShape> raster_shape =
      std::make_unique<RasterShape>(std::move(intervals), gfx::Size());
  raster_shape->writing_mode_ = writing_mode;
  raster_shape->margin_ = margin;
  return std::move(raster_shape);
}

static bool ExtractImageData(Image* image,
                             const gfx::Size& image_size,
                             ArrayBufferContents& contents,
                             RespectImageOrientationEnum respect_orientation) {
  if (!image)
    return false;

  // Compute the SkImageInfo for the output.
  SkImageInfo dst_info = SkImageInfo::Make(
      image_size.width(), image_size.height(), kN32_SkColorType,
      kPremul_SkAlphaType, SkColorSpace::MakeSRGB());

  // Populate |contents| with newly allocated and zero-initialized data, big
  // enough for |dst_info|.
  size_t dst_size_bytes = dst_info.computeMinByteSize();
  {
    if (SkImageInfo::ByteSizeOverflowed(dst_size_bytes) ||
        dst_size_bytes > v8::TypedArray::kMaxByteLength) {
      return false;
    }
    ArrayBufferContents result(dst_size_bytes, 1,
                               ArrayBufferContents::kNotShared,
                               ArrayBufferContents::kZeroInitialize);
    if (result.DataLength() != dst_size_bytes)
      return false;
    result.Transfer(contents);
  }

  // Set |surface| to draw directly to |contents|.
  const SkSurfaceProps disable_lcd_props;
  sk_sp<SkSurface> surface = SkSurfaces::WrapPixels(
      dst_info, contents.Data(), dst_info.minRowBytes(), &disable_lcd_props);
  if (!surface)
    return false;

  // FIXME: This is not totally correct but it is needed to prevent shapes
  // that loads SVG Images during paint invalidations to mark layoutObjects
  // for layout, which is not allowed. See https://crbug.com/429346
  ImageObserverDisabler disabler(image);
  cc::PaintFlags flags;
  gfx::RectF image_source_rect(gfx::SizeF(image->Size()));
  gfx::Rect image_dest_rect(image_size);
  SkiaPaintCanvas canvas(surface->getCanvas());
  canvas.clear(SkColors::kTransparent);
  ImageDrawOptions draw_options;
  draw_options.respect_orientation = respect_orientation;
  draw_options.clamping_mode = Image::kDoNotClampImageToSourceRect;
  image->Draw(&canvas, flags, gfx::RectF(image_dest_rect), image_source_rect,
              draw_options);
  return true;
}

static std::unique_ptr<RasterShapeIntervals> ExtractIntervalsFromImageData(
    ArrayBufferContents& contents,
    float threshold,
    int content_block_size,
    const gfx::Size& image_physical_size,
    const gfx::Rect& image_logical_rect,
    const gfx::Rect& margin_logical_rect,
    WritingMode writing_mode) {
  DOMArrayBuffer* array_buffer = DOMArrayBuffer::Create(contents);
  DOMUint8ClampedArray* pixel_array =
      DOMUint8ClampedArray::Create(array_buffer, 0, array_buffer->ByteLength());

  uint8_t alpha_pixel_threshold = threshold * 255;

  DCHECK_EQ(image_logical_rect.size().Area64() * 4, pixel_array->length());

  const int image_inline_size = image_logical_rect.width();
  const int image_inline_start = image_logical_rect.x();
  const int image_block_start = image_logical_rect.y();
  const int image_block_end = image_logical_rect.bottom();
  const int margin_box_block_size = margin_logical_rect.height();
  const int margin_block_start = margin_logical_rect.y();
  const int margin_block_end = margin_block_start + margin_box_block_size;

  const int min_buffer_y = std::max({0, margin_block_start, image_block_start});
  const int max_buffer_y =
      std::min({content_block_size, image_block_end, margin_block_end});

  std::unique_ptr<RasterShapeIntervals> intervals =
      std::make_unique<RasterShapeIntervals>(margin_box_block_size,
                                             -margin_block_start);

  LogicalPixelScanner scanner(*pixel_array, image_physical_size, writing_mode);
  for (int y = image_block_start; y < min_buffer_y; ++y) {
    scanner.NextLine();
  }
  for (int y = min_buffer_y; y < max_buffer_y; ++y, scanner.NextLine()) {
    int start_x = -1;
    for (int x = 0; x < image_inline_size; ++x, scanner.Next()) {
      uint8_t alpha = scanner.GetAlpha();
      bool alpha_above_threshold = alpha > alpha_pixel_threshold;
      if (start_x == -1 && alpha_above_threshold) {
        start_x = x;
      } else if (start_x != -1 &&
                 (!alpha_above_threshold || x == image_inline_size - 1)) {
        int end_x = alpha_above_threshold ? x + 1 : x;
        intervals->IntervalAt(y).Unite(IntShapeInterval(
            start_x + image_inline_start, end_x + image_inline_start));
        start_x = -1;
      }
    }
  }
  return intervals;
}

static bool IsValidRasterShapeSize(const gfx::Size& size) {
  // Some platforms don't limit MaxDecodedImageBytes.
  constexpr size_t size32_max_bytes = 0xFFFFFFFF / 4;
  static const size_t max_image_size_bytes =
      std::min(size32_max_bytes, Platform::Current()->MaxDecodedImageBytes());
  return size.Area64() * 4 < max_image_size_bytes;
}

std::unique_ptr<Shape> Shape::CreateRasterShape(
    Image* image,
    float threshold,
    int content_block_size,
    const gfx::Rect& image_logical_rect,
    const gfx::Rect& margin_logical_rect,
    WritingMode writing_mode,
    float margin,
    RespectImageOrientationEnum respect_orientation) {
  gfx::Size margin_box_size = margin_logical_rect.size();
  if (!IsValidRasterShapeSize(margin_box_size) ||
      !IsValidRasterShapeSize(image_logical_rect.size())) {
    return CreateEmptyRasterShape(writing_mode, margin);
  }

  ArrayBufferContents contents;
  gfx::Size image_physical_size = image_logical_rect.size();
  if (!IsHorizontalWritingMode(writing_mode)) {
    image_physical_size.Transpose();
  }
  if (!ExtractImageData(image, image_physical_size, contents,
                        respect_orientation)) {
    return CreateEmptyRasterShape(writing_mode, margin);
  }

  std::unique_ptr<RasterShapeIntervals> intervals =
      ExtractIntervalsFromImageData(contents, threshold, content_block_size,
                                    image_physical_size, image_logical_rect,
                                    margin_logical_rect, writing_mode);
  std::unique_ptr<RasterShape> raster_shape =
      std::make_unique<RasterShape>(std::move(intervals), margin_box_size);
  raster_shape->writing_mode_ = writing_mode;
  raster_shape->margin_ = margin;
  return std::move(raster_shape);
}

std::unique_ptr<Shape> Shape::CreateLayoutBoxShape(
    const FloatRoundedRect& rounded_rect,
    WritingMode writing_mode,
    float margin) {
  gfx::RectF rect(rounded_rect.Rect().size());
  WritingModeConverter converter(
      {writing_mode, TextDirection::kLtr},
      PhysicalSize::FromSizeFFloor(rounded_rect.Rect().size()));
  std::unique_ptr<Shape> shape =
      CreateInsetShape(BoxShape::ToLogical(rounded_rect, converter));
  shape->writing_mode_ = writing_mode;
  shape->margin_ = margin;

  return shape;
}

}  // namespace blink

"""

```