Response:
My thinking process to answer the request about `shape_outside_info.cc` goes like this:

1. **Understand the Core Purpose:** The filename `shape_outside_info.cc` immediately suggests it deals with the CSS `shape-outside` property. My primary goal is to explain how this file helps implement that CSS feature.

2. **Identify Key Concepts:** I scan the code for relevant terms: `ShapeValue`, `ReferenceBox`, `ComputedShape`, `WritingMode`, `LayoutBox`, `StyleImage`, `Shape`. These become the building blocks of my explanation.

3. **Break Down Functionality:** I go through the methods and functions defined in the file and try to understand their individual roles:
    * **`SetReferenceBoxLogicalSize`:**  Handles the different `box-sizing` values (`margin-box`, `border-box`, etc.) for `shape-outside`. It also tracks usage via `UseCounter`.
    * **`SetPercentageResolutionInlineSize`:**  Deals with how percentages in `shape-margin` are resolved.
    * **`CreateShapeForImage`:**  Specifically handles `shape-outside: url(...)`, involving image loading, orientation, and thresholding.
    * **`ComputedShape`:**  The core function that actually creates the `Shape` object based on the `shape-outside` value (either a basic shape, an image, or a box). It handles caching to avoid redundant computations.
    * **`BlockStartOffset` and `InlineStartOffset`:** These functions are crucial for positioning the shape relative to the element's box. They account for different reference boxes.
    * **`IsEnabledFor`:** Determines if `shape-outside` should be active for a given element, checking for floats, the presence of a `shape-outside` value, and image loading status (if applicable).
    * **`ComputedShapePhysicalBoundingBox`:** Calculates the physical bounding box of the generated shape, taking writing modes into account.
    * **`ShapeToLayoutObjectPoint`:** Converts coordinates from the shape's coordinate system to the layout object's coordinate system.

4. **Connect to Web Technologies:** I need to explain how this C++ code relates to JavaScript, HTML, and CSS.
    * **CSS:** The direct connection is the `shape-outside` property. I give examples of different `shape-outside` values and how they influence the text flow. I also mention `shape-margin` and `shape-image-threshold`.
    * **HTML:**  HTML provides the structure to which the CSS (and thus `shape-outside`) is applied. I illustrate this with a simple example of an image with `shape-outside`.
    * **JavaScript:**  While not directly interacting with this C++ file at runtime, JavaScript can manipulate the CSS `shape-outside` property, indirectly triggering the logic in this file. I explain this connection.

5. **Illustrate with Examples and Scenarios:**  Concrete examples make the explanation much clearer.
    * **Input/Output:**  For `SetReferenceBoxLogicalSize`, I show how different `box-sizing` values affect the calculated reference box size. For `ComputedShape`, I illustrate how a `circle()` shape value leads to a circular shape.
    * **User/Programming Errors:** I focus on common mistakes related to `shape-outside`: forgetting to float the element, incorrect image URLs, and security restrictions with cross-origin images.

6. **Structure and Clarity:**  I organize the information logically:
    * Start with a high-level overview of the file's purpose.
    * Explain the core functionalities.
    * Connect to web technologies with examples.
    * Provide input/output examples for clarity.
    * Address common errors.
    * Use clear and concise language.

7. **Refine and Review:**  I reread my explanation to ensure accuracy, completeness, and clarity. I check for any technical jargon that needs further explanation. I make sure the examples are easy to understand.

Essentially, my process is to dissect the code, understand its role in the browser's layout engine, and then bridge the gap between this low-level implementation and the high-level web technologies that developers use. The goal is to provide a comprehensive and understandable explanation for someone familiar with web development but potentially less familiar with the internals of a browser engine.
这个文件 `shape_outside_info.cc` 是 Chromium Blink 引擎中负责处理 CSS `shape-outside` 属性的核心组件之一。它的主要功能是计算和管理与 `shape-outside` 属性相关的各种信息，以便在渲染网页时，能够让浮动元素周围的内容按照指定的形状进行环绕。

以下是它的具体功能，并解释了它与 JavaScript、HTML 和 CSS 的关系，以及可能涉及的逻辑推理和常见错误：

**功能列举:**

1. **存储和管理 `shape-outside` 相关信息:**
   - 存储与应用了 `shape-outside` 属性的布局盒 (LayoutBox) 相关联的形状信息，例如形状的类型 (圆形、椭圆、多边形、图像等)、形状的值、以及相关的 margin。
   - 维护计算出的形状 (Shape) 对象，该对象表示实际的环绕路径。
   - 跟踪和管理形状的参考框 (reference box)，这决定了形状的坐标系统的基准，可以是 `margin-box`, `border-box`, `padding-box`, 或 `content-box`。

2. **计算形状的参考框大小 (Reference Box Sizing):**
   - 根据 `shape-outside` 属性中指定的 `box` 值 (如 `margin-box`, `border-box` 等) 和布局盒的尺寸信息，计算出形状的参考框的逻辑尺寸 (LogicalSize)。
   - 例如，如果 `shape-outside: circle(50%) border-box;`，则参考框的大小将是布局盒的边框盒大小。

3. **处理基于图像的形状 (`shape-outside: url(...)`):**
   - 当 `shape-outside` 的值是图像 URL 时，负责加载图像。
   - 基于图像的 alpha 通道或亮度值，创建一个表示环绕路径的形状。
   - 考虑 `shape-image-threshold` 属性，用于控制图像透明度的阈值。
   - 处理图像的加载状态和安全策略（例如，跨域访问）。

4. **计算和缓存形状 (Computed Shape):**
   - 根据 `shape-outside` 的值和参考框的大小，计算出实际的形状对象。
   - 缓存已计算出的形状，避免重复计算，提高性能。
   - 处理不同类型的形状值：
     - **基本形状 (Basic Shapes):** 例如 `circle()`, `ellipse()`, `polygon()`.
     - **图像 (Image):** 基于图像的透明度或亮度生成形状。
     - **盒模型 (Box):** 使用元素的盒模型边界作为形状。

5. **计算形状的偏移量 (Offsets):**
   - 计算形状相对于布局盒的偏移量，包括块起始偏移量 (BlockStartOffset) 和内联起始偏移量 (InlineStartOffset)。
   - 这些偏移量用于在布局过程中正确地定位形状。

6. **判断 `shape-outside` 是否生效 (Is Enabled For):**
   - 检查应用了 `shape-outside` 属性的布局盒是否满足生效的条件，例如是否为浮动元素，以及图像是否已加载并可渲染。

7. **计算形状的物理边界框 (Computed Shape Physical Bounding Box):**
   - 计算形状在物理坐标系中的边界框，考虑到书写模式 (writing mode) 和布局方向。

8. **坐标转换 (Shape to Layout Object Point):**
   - 提供将形状坐标系中的点转换为布局对象坐标系中的点的方法，这在进行 hit-testing 或其他几何计算时非常有用。

**与 JavaScript, HTML, CSS 的关系:**

* **CSS:** 这个文件直接实现了 CSS `shape-outside` 属性的功能。它解析 CSS 样式，并根据 `shape-outside` 的值进行计算。例如：
    ```css
    .float-element {
      float: left;
      width: 200px;
      height: 200px;
      shape-outside: circle(50%); /* 使用圆形作为环绕形状 */
    }
    .shape-image {
      float: right;
      width: 150px;
      height: 150px;
      shape-outside: url(image.png); /* 使用图片定义环绕形状 */
      shape-margin: 10px; /* 设置形状的外边距 */
    }
    ```
    `shape_outside_info.cc` 会解析这些 CSS 规则，并生成相应的形状。

* **HTML:** HTML 提供了结构，`shape-outside` 属性应用于 HTML 元素。例如：
    ```html
    <div class="float-element"></div>
    <p>这是一段围绕浮动元素环绕的文本。</p>

    <div class="shape-image"></div>
    <p>这段文字会根据图片的形状进行环绕。</p>
    ```
    `shape_outside_info.cc` 会作用于这些 HTML 结构中应用了 `shape-outside` 的元素。

* **JavaScript:** JavaScript 可以动态地修改元素的 CSS 样式，包括 `shape-outside` 属性。当 JavaScript 修改 `shape-outside` 时，会触发 Blink 引擎重新计算布局，并可能调用 `shape_outside_info.cc` 中的相关函数来更新形状信息。例如：
    ```javascript
    const element = document.querySelector('.float-element');
    element.style.shapeOutside = 'ellipse(60% 40%)'; // 使用 JavaScript 修改形状
    ```

**逻辑推理和假设输入与输出:**

假设输入一个应用了 `shape-outside` 属性的 `LayoutBox` 对象，其 CSS 样式为：

```css
.shaped {
  float: left;
  width: 100px;
  height: 150px;
  shape-outside: polygon(0 0, 100% 0, 50% 100%, 0 50%);
  shape-margin: 5px;
}
```

**假设输入:**

- 一个 `LayoutBox` 对象，表示一个宽度为 100px，高度为 150px 的浮动元素。
- `shape-outside` 属性值为 `polygon(0 0, 100% 0, 50% 100%, 0 50%)`。
- `shape-margin` 属性值为 `5px`。
- 参考框默认为 `margin-box`。

**逻辑推理过程:**

1. **解析 `shape-outside` 值:** `shape_outside_info.cc` 会解析 `polygon(...)` 值，提取多边形的顶点坐标。
2. **确定参考框:** 默认为 `margin-box`，因此会考虑元素的 margin。
3. **计算形状:** 根据多边形的顶点和参考框，创建一个表示该多边形的 `Shape` 对象。
4. **应用 `shape-margin`:** 在计算出的形状的基础上，向外扩展 `shape-margin` 的距离 (5px)。
5. **存储信息:** 将计算出的形状和相关信息存储在与该 `LayoutBox` 关联的 `ShapeOutsideInfo` 对象中。

**假设输出:**

- 一个 `Shape` 对象，表示一个经过 margin 扩展的梯形。该梯形的顶点坐标会根据元素的尺寸和 `shape-margin` 进行计算。
- 形状的偏移量信息，用于在布局时将形状定位到正确的位置。

**用户或编程常见的使用错误:**

1. **忘记设置 `float` 属性:** `shape-outside` 属性只对浮动元素生效。如果元素没有设置 `float: left` 或 `float: right`，`shape-outside` 将不会产生效果。

   ```css
   .element {
     /* shape-outside 不会生效，因为没有 float */
     width: 200px;
     height: 200px;
     shape-outside: circle(50%);
   }
   ```

2. **错误的图像 URL 或跨域问题:** 当使用 `shape-outside: url(...)` 时，如果图像 URL 不存在或存在跨域访问限制，形状将无法正确创建。浏览器控制台通常会显示相关错误信息。

   ```css
   .shaped-image {
     float: left;
     width: 100px;
     height: 100px;
     shape-outside: url(nonexistent.png); /* 错误的 URL */
   }
   ```

3. **基本形状的语法错误:** 如果 `circle()`, `ellipse()`, `polygon()` 等基本形状的语法不正确，`shape-outside` 将会被忽略。

   ```css
   .shaped-circle {
     float: left;
     width: 100px;
     height: 100px;
     shape-outside: circle(50); /* 缺少单位 */
   }
   ```

4. **误解参考框的概念:** 不理解 `margin-box`, `border-box`, `padding-box`, `content-box` 的区别，导致形状的计算基准不正确。

   ```css
   .shaped-box {
     float: left;
     width: 100px;
     height: 100px;
     padding: 20px;
     border: 5px solid black;
     shape-outside: circle(50%) content-box; /* 基于 content-box 计算圆形 */
   }
   ```
   如果预期是基于包含 padding 和 border 的区域计算，则应该使用 `border-box`。

5. **过度依赖 `shape-margin` 导致内容重叠:** 如果 `shape-margin` 设置过大，可能导致环绕的内容与浮动元素本身或其他内容发生不必要的重叠。

总而言之，`shape_outside_info.cc` 是 Blink 引擎中实现 CSS `shape-outside` 属性的关键部分，负责计算和管理形状信息，使得网页能够呈现出更加灵活和美观的文本环绕效果。 它与 CSS 样式声明紧密相关，并在 HTML 结构的基础上发挥作用。JavaScript 可以动态地影响其行为，但核心的计算逻辑由 C++ 代码实现。

Prompt: 
```
这是目录为blink/renderer/core/layout/shapes/shape_outside_info.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/layout/shapes/shape_outside_info.h"

#include <memory>

#include "base/auto_reset.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/layout/geometry/logical_rect.h"
#include "third_party/blink/renderer/core/layout/geometry/writing_mode_converter.h"
#include "third_party/blink/renderer/core/layout/layout_block_flow.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/layout_image.h"
#include "third_party/blink/renderer/core/paint/rounded_border_geometry.h"
#include "third_party/blink/renderer/platform/geometry/length_functions.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"

namespace blink {

namespace {

gfx::Rect ToPixelSnappedLogicalRect(const LogicalRect& rect) {
  return gfx::Rect(
      rect.offset.inline_offset.Round(), rect.offset.block_offset.Round(),
      SnapSizeToPixel(rect.size.inline_size, rect.offset.inline_offset),
      SnapSizeToPixel(rect.size.block_size, rect.offset.block_offset));
}

// Unlike LayoutBoxModelObject::PhysicalBorderToLogical(), this function
// applies container's WritingDirectionMode.
PhysicalToLogicalGetter<LayoutUnit, LayoutBox> LogicalBorder(
    const LayoutBox& layout_box,
    const ComputedStyle& container_style) {
  return PhysicalToLogicalGetter<LayoutUnit, LayoutBox>(
      container_style.GetWritingDirection(), layout_box, &LayoutBox::BorderTop,
      &LayoutBox::BorderRight, &LayoutBox::BorderBottom,
      &LayoutBox::BorderLeft);
}

// Unlike LayoutBoxModelObject::PhysicalPaddingToLogical(), this function
// applies container's WritingDirectionMode.
PhysicalToLogicalGetter<LayoutUnit, LayoutBox> LogicalPadding(
    const LayoutBox& layout_box,
    const ComputedStyle& container_style) {
  return PhysicalToLogicalGetter<LayoutUnit, LayoutBox>(
      container_style.GetWritingDirection(), layout_box, &LayoutBox::PaddingTop,
      &LayoutBox::PaddingRight, &LayoutBox::PaddingBottom,
      &LayoutBox::PaddingLeft);
}

}  // namespace

CSSBoxType ReferenceBox(const ShapeValue& shape_value) {
  if (shape_value.CssBox() == CSSBoxType::kMissing)
    return CSSBoxType::kMargin;
  return shape_value.CssBox();
}

void ShapeOutsideInfo::SetReferenceBoxLogicalSize(
    LogicalSize new_reference_box_logical_size,
    LogicalSize margin_size) {
  Document& document = layout_box_->GetDocument();
  bool is_horizontal_writing_mode =
      layout_box_->ContainingBlock()->StyleRef().IsHorizontalWritingMode();

  LogicalSize margin_box_for_use_counter = new_reference_box_logical_size;
  margin_box_for_use_counter.Expand(margin_size.inline_size,
                                    margin_size.block_size);

  const ShapeValue& shape_value = *layout_box_->StyleRef().ShapeOutside();
  switch (ReferenceBox(shape_value)) {
    case CSSBoxType::kMargin:
      UseCounter::Count(document, WebFeature::kShapeOutsideMarginBox);
      new_reference_box_logical_size.Expand(margin_size.inline_size,
                                            margin_size.block_size);
      break;
    case CSSBoxType::kBorder:
      UseCounter::Count(document, WebFeature::kShapeOutsideBorderBox);
      break;
    case CSSBoxType::kPadding:
      UseCounter::Count(document, WebFeature::kShapeOutsidePaddingBox);
      if (is_horizontal_writing_mode) {
        new_reference_box_logical_size.Shrink(layout_box_->BorderWidth(),
                                              layout_box_->BorderHeight());
      } else {
        new_reference_box_logical_size.Shrink(layout_box_->BorderHeight(),
                                              layout_box_->BorderWidth());
      }

      if (new_reference_box_logical_size != margin_box_for_use_counter) {
        UseCounter::Count(
            document,
            WebFeature::kShapeOutsidePaddingBoxDifferentFromMarginBox);
      }
      break;
    case CSSBoxType::kContent: {
      bool is_shape_image = shape_value.GetType() == ShapeValue::kImage;

      if (!is_shape_image)
        UseCounter::Count(document, WebFeature::kShapeOutsideContentBox);

      if (is_horizontal_writing_mode) {
        new_reference_box_logical_size.Shrink(
            layout_box_->BorderAndPaddingWidth(),
            layout_box_->BorderAndPaddingHeight());
      } else {
        new_reference_box_logical_size.Shrink(
            layout_box_->BorderAndPaddingHeight(),
            layout_box_->BorderAndPaddingWidth());
      }

      if (!is_shape_image &&
          new_reference_box_logical_size != margin_box_for_use_counter) {
        UseCounter::Count(
            document,
            WebFeature::kShapeOutsideContentBoxDifferentFromMarginBox);
      }
      break;
    }
    case CSSBoxType::kMissing:
      NOTREACHED();
  }

  new_reference_box_logical_size.ClampNegativeToZero();

  if (reference_box_logical_size_ == new_reference_box_logical_size)
    return;
  MarkShapeAsDirty();
  reference_box_logical_size_ = new_reference_box_logical_size;
}

void ShapeOutsideInfo::SetPercentageResolutionInlineSize(
    LayoutUnit percentage_resolution_inline_size) {
  if (percentage_resolution_inline_size_ == percentage_resolution_inline_size)
    return;

  MarkShapeAsDirty();
  percentage_resolution_inline_size_ = percentage_resolution_inline_size;
}

static bool CheckShapeImageOrigin(Document& document,
                                  const StyleImage& style_image) {
  String failing_url;
  if (style_image.IsAccessAllowed(failing_url))
    return true;
  String url_string = failing_url.IsNull() ? "''" : failing_url;
  document.AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
      mojom::ConsoleMessageSource::kSecurity,
      mojom::ConsoleMessageLevel::kError,
      "Unsafe attempt to load URL " + url_string + "."));
  return false;
}

static PhysicalRect GetShapeImagePhysicalMarginRect(
    const LayoutBox& layout_box,
    const PhysicalSize& reference_physical_size) {
  PhysicalBoxStrut margin_border_padding = layout_box.MarginBoxOutsets() +
                                           layout_box.BorderOutsets() +
                                           layout_box.PaddingOutsets();
  return PhysicalRect(
      -margin_border_padding.left, -margin_border_padding.top,
      margin_border_padding.HorizontalSum() + reference_physical_size.width,
      margin_border_padding.VerticalSum() + reference_physical_size.height);
}

PhysicalSize ShapeOutsideInfo::ReferenceBoxPhysicalSize() const {
  return ToPhysicalSize(
      reference_box_logical_size_,
      layout_box_->ContainingBlock()->Style()->GetWritingMode());
}

std::unique_ptr<Shape> ShapeOutsideInfo::CreateShapeForImage(
    StyleImage* style_image,
    float shape_image_threshold,
    WritingMode writing_mode,
    float margin) const {
  DCHECK(!style_image->IsPendingImage());

  PhysicalSize reference_physical_size = ReferenceBoxPhysicalSize();
  RespectImageOrientationEnum respect_orientation =
      style_image->ForceOrientationIfNecessary(
          layout_box_->StyleRef().ImageOrientation());

  const gfx::SizeF image_size = style_image->ImageSize(
      layout_box_->StyleRef().EffectiveZoom(),
      gfx::SizeF(reference_physical_size), respect_orientation);

  WritingModeConverter converter({writing_mode, TextDirection::kLtr},
                                 reference_physical_size);
  LogicalRect margin_rect = converter.ToLogical(
      GetShapeImagePhysicalMarginRect(*layout_box_, reference_physical_size));
  margin_rect.size.inline_size =
      margin_rect.size.inline_size.ClampNegativeToZero();
  margin_rect.size.block_size =
      margin_rect.size.block_size.ClampNegativeToZero();

  const PhysicalRect image_physical_rect =
      layout_box_->IsLayoutImage()
          ? To<LayoutImage>(layout_box_.Get())->ReplacedContentRect()
          : PhysicalRect({}, PhysicalSize::FromSizeFRound(image_size));
  gfx::Rect image_rect =
      ToPixelSnappedLogicalRect(converter.ToLogical(image_physical_rect));

  scoped_refptr<Image> image =
      style_image->GetImage(*layout_box_, layout_box_->GetDocument(),
                            layout_box_->StyleRef(), image_size);

  return Shape::CreateRasterShape(
      image.get(), shape_image_threshold,
      reference_box_logical_size_.block_size.Floor(), image_rect,
      ToPixelSnappedLogicalRect(margin_rect), writing_mode, margin,
      respect_orientation);
}

const Shape& ShapeOutsideInfo::ComputedShape() const {
  if (Shape* shape = shape_.get())
    return *shape;

  base::AutoReset<bool> is_in_computing_shape(&is_computing_shape_, true);

  const ComputedStyle& style = *layout_box_->Style();
  DCHECK(layout_box_->ContainingBlock());
  const LayoutBlock& containing_block = *layout_box_->ContainingBlock();
  const ComputedStyle& containing_block_style = containing_block.StyleRef();

  WritingMode writing_mode = containing_block_style.GetWritingMode();
  // Make sure contentWidth is not negative. This can happen when containing
  // block has a vertical scrollbar and its content is smaller than the
  // scrollbar width.
  LayoutUnit percentage_resolution_inline_size =
      containing_block.IsLayoutNGObject()
          ? percentage_resolution_inline_size_
          : std::max(LayoutUnit(), containing_block.ContentWidth());

  float margin =
      FloatValueForLength(layout_box_->StyleRef().ShapeMargin(),
                          percentage_resolution_inline_size.ToFloat());

  float shape_image_threshold = style.ShapeImageThreshold();
  DCHECK(style.ShapeOutside());
  const ShapeValue& shape_value = *style.ShapeOutside();

  switch (shape_value.GetType()) {
    case ShapeValue::kShape:
      DCHECK(shape_value.Shape());
      shape_ =
          Shape::CreateShape(shape_value.Shape(), reference_box_logical_size_,
                             writing_mode, margin);
      break;
    case ShapeValue::kImage:
      DCHECK(shape_value.GetImage());
      DCHECK(shape_value.GetImage()->IsLoaded());
      DCHECK(shape_value.GetImage()->CanRender());
      shape_ = CreateShapeForImage(shape_value.GetImage(),
                                   shape_image_threshold, writing_mode, margin);
      break;
    case ShapeValue::kBox: {
      const FloatRoundedRect& shape_rect = RoundedBorderGeometry::RoundedBorder(
          style, PhysicalRect(PhysicalOffset(), ReferenceBoxPhysicalSize()));
      shape_ = Shape::CreateLayoutBoxShape(shape_rect, writing_mode, margin);
      break;
    }
  }

  DCHECK(shape_);
  return *shape_;
}

LayoutUnit ShapeOutsideInfo::BlockStartOffset() const {
  const ComputedStyle& container_style =
      layout_box_->ContainingBlock()->StyleRef();
  switch (ReferenceBox(*layout_box_->StyleRef().ShapeOutside())) {
    case CSSBoxType::kMargin:
      return -layout_box_->MarginBlockStart(&container_style);
    case CSSBoxType::kBorder:
      return LayoutUnit();
    case CSSBoxType::kPadding:
      return LogicalBorder(*layout_box_, container_style).BlockStart();
    case CSSBoxType::kContent:
      return LogicalBorder(*layout_box_, container_style).BlockStart() +
             LogicalPadding(*layout_box_, container_style).BlockStart();
    case CSSBoxType::kMissing:
      break;
  }

  NOTREACHED();
}

LayoutUnit ShapeOutsideInfo::InlineStartOffset() const {
  const ComputedStyle& container_style =
      layout_box_->ContainingBlock()->StyleRef();
  switch (ReferenceBox(*layout_box_->StyleRef().ShapeOutside())) {
    case CSSBoxType::kMargin:
      return -layout_box_->MarginInlineStart(&container_style);
    case CSSBoxType::kBorder:
      return LayoutUnit();
    case CSSBoxType::kPadding:
      return LogicalBorder(*layout_box_, container_style).InlineStart();
    case CSSBoxType::kContent:
      return LogicalBorder(*layout_box_, container_style).InlineStart() +
             LogicalPadding(*layout_box_, container_style).InlineStart();
    case CSSBoxType::kMissing:
      break;
  }

  NOTREACHED();
}

bool ShapeOutsideInfo::IsEnabledFor(const LayoutBox& box) {
  ShapeValue* shape_value = box.StyleRef().ShapeOutside();
  if (!box.IsFloating() || !shape_value)
    return false;

  switch (shape_value->GetType()) {
    case ShapeValue::kShape:
      return shape_value->Shape();
    case ShapeValue::kImage: {
      StyleImage* image = shape_value->GetImage();
      DCHECK(image);
      return image->IsLoaded() && image->CanRender() &&
             CheckShapeImageOrigin(box.GetDocument(), *image);
    }
    case ShapeValue::kBox:
      return true;
  }

  return false;
}

PhysicalRect ShapeOutsideInfo::ComputedShapePhysicalBoundingBox() const {
  LogicalRect logical_box = ComputedShape().ShapeMarginLogicalBoundingBox();
  // TODO(crbug.com/1463823): The logic of this function looks incorrect.
  PhysicalRect physical_bounding_box(
      logical_box.offset.inline_offset, logical_box.offset.block_offset,
      logical_box.size.inline_size, logical_box.size.block_size);
  physical_bounding_box.offset.left += InlineStartOffset();

  if (layout_box_->StyleRef().IsFlippedBlocksWritingMode()) {
    physical_bounding_box.offset.top =
        layout_box_->LogicalHeight() - physical_bounding_box.Bottom();
  } else {
    physical_bounding_box.offset.top += BlockStartOffset();
  }

  if (!layout_box_->StyleRef().IsHorizontalWritingMode()) {
    physical_bounding_box = PhysicalRect(
        physical_bounding_box.offset.top, physical_bounding_box.offset.left,
        physical_bounding_box.size.height, physical_bounding_box.size.width);
  } else {
    physical_bounding_box.offset.top += BlockStartOffset();
  }

  return physical_bounding_box;
}

gfx::PointF ShapeOutsideInfo::ShapeToLayoutObjectPoint(
    gfx::PointF point) const {
  gfx::PointF result = gfx::PointF(point.x() + InlineStartOffset(),
                                   point.y() + BlockStartOffset());
  if (layout_box_->StyleRef().IsFlippedBlocksWritingMode())
    result.set_y(layout_box_->LogicalHeight() - result.y());
  if (!layout_box_->StyleRef().IsHorizontalWritingMode())
    result.Transpose();
  return result;
}

// static
ShapeOutsideInfo::InfoMap& ShapeOutsideInfo::GetInfoMap() {
  DEFINE_STATIC_LOCAL(Persistent<InfoMap>, static_info_map,
                      (MakeGarbageCollected<InfoMap>()));
  return *static_info_map;
}

void ShapeOutsideInfo::Trace(Visitor* visitor) const {
  visitor->Trace(layout_box_);
}

}  // namespace blink

"""

```