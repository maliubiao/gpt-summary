Response:
Let's break down the thought process for analyzing this C++ code and generating the descriptive response.

1. **Understand the Goal:** The request asks for the functionality of the `FloatRoundedRect` class in Chromium's Blink rendering engine, its relation to web technologies (JavaScript, HTML, CSS), logical reasoning with examples, and common usage errors.

2. **Initial Code Scan and Identification of Core Functionality:**
   - The filename `float_rounded_rect.cc` immediately suggests it deals with rounded rectangles with floating-point coordinates.
   - The `#include` directives point to related geometry classes (`gfx::RectF`, `gfx::SizeF`, `gfx::RRectF`, `gfx::QuadF`, `gfx::OutsetsF`) and utility classes (`wtf::String`). This hints at the class's purpose in handling geometric shapes.
   - The constructor overloads reveal different ways to initialize a `FloatRoundedRect`: from a simple rectangle, from a rectangle and radii, from individual corner radii, and from a `gfx::RRectF` (rounded rectangle). This indicates flexibility in how rounded rectangles can be defined.
   - The `Radii` nested struct is crucial, clearly responsible for managing the corner radii. Its methods like `SetMinimumRadius`, `UniformRadius`, `Scale`, `Outset`, and `OutsetForMarginOrShadow` suggest operations related to manipulating and adjusting these radii.
   - The `FloatRoundedRect` methods like `XInterceptsAtY`, `Outset`, `OutsetForMarginOrShadow`, `OutsetForShapeMargin`, `IntersectsQuad`, `ConstrainRadii`, and `IsRenderable` reveal the class's capabilities in geometric calculations, transformations, and validation.

3. **Deconstruct Functionality by Method/Section:**  Go through the code method by method, understanding the purpose of each.

   - **Constructors:** How to create `FloatRoundedRect` objects.
   - **`Radii` struct methods:** Focus on how corner radii are managed (setting minimums, checking uniformity, scaling, offsetting). The comments about CSS specifications in `OutsetForMarginOrShadow` are a key connection to web standards.
   - **`XInterceptsAtY`:**  Determine the horizontal intersection points at a given vertical coordinate. This is important for hit-testing and shape analysis.
   - **`Outset` methods:**  How the rounded rectangle expands or contracts. The different `Outset` variations (`Outset`, `OutsetForMarginOrShadow`, `OutsetForShapeMargin`) are important distinctions.
   - **`IntersectsQuad`:**  Checks if the rounded rectangle overlaps with a quadrilateral. This is crucial for determining visibility and interactions.
   - **`ConstrainRadii`:**  Ensures that the radii are not too large for the rectangle's dimensions, preventing rendering issues.
   - **`IsRenderable`:** A validation check to ensure the rounded rectangle can be properly rendered.
   - **`ToString` operators:**  For debugging and logging.

4. **Connect to Web Technologies (JavaScript, HTML, CSS):**  This requires linking the C++ functionality to how these concepts are expressed in the browser.

   - **CSS `border-radius`:** The most direct link. Explain how the `FloatRoundedRect` represents the visual effect of CSS `border-radius`.
   - **CSS `margin` and `box-shadow`:**  The `OutsetForMarginOrShadow` method explicitly mentions these, making the connection clear. Explain how the class accounts for the expanded area due to margins and shadows.
   - **CSS `shape-margin`:**  The `OutsetForShapeMargin` method provides the direct connection here.
   - **JavaScript (via DOM APIs):** While the C++ code isn't directly invoked by JavaScript, explain how JavaScript manipulation of CSS properties (like `border-radius`, `margin`, `box-shadow`, `shape-margin`) indirectly uses this C++ class under the hood in the rendering engine.
   - **HTML:**  HTML provides the structure on which CSS styles are applied. Mention that the `FloatRoundedRect` ultimately renders elements defined in HTML.

5. **Logical Reasoning with Examples (Input/Output):** Choose specific methods and demonstrate their behavior with simple examples.

   - **`ConstrainRadii`:**  A good example because it shows how the radii are adjusted based on the rectangle's size. Provide a clear input (rectangle and radii) and the expected output (adjusted radii).
   - **`XInterceptsAtY`:** Demonstrate how the intersection points are calculated at different `y` values, considering rounded corners.

6. **Common Usage Errors:** Think about how developers might misuse the concepts represented by this class, even if they don't directly interact with the C++ code.

   - **Overlapping radii:**  Relate this to the `ConstrainRadii` function and explain why excessively large radii can lead to unexpected rendering.
   - **Incorrect `shape-margin` usage:**  Highlight the potential for visual artifacts if `shape-margin` is not used carefully with rounded corners.

7. **Structure and Refine the Response:** Organize the information logically with clear headings and bullet points. Use precise language and avoid jargon where possible. Ensure the examples are easy to understand.

8. **Review and Iterate:**  Read through the generated response, checking for clarity, accuracy, and completeness. Are there any ambiguities?  Could the examples be clearer? Is the connection to web technologies well-explained?

**Self-Correction/Refinement During the Process:**

- **Initial thought:**  Focus solely on the geometric calculations.
- **Correction:** Realize the importance of connecting the C++ code to the higher-level web technologies that developers interact with.
- **Initial thought:**  Provide only the function names.
- **Correction:**  Elaborate on the purpose and behavior of each function with brief explanations.
- **Initial thought:**  Use complex mathematical examples.
- **Correction:** Simplify the examples for better understanding. Focus on demonstrating the core logic.
- **Initial thought:** Assume the reader is a C++ expert.
- **Correction:** Explain concepts in a way that is understandable to someone with a web development background.

By following this structured thought process and incorporating self-correction, a comprehensive and informative response like the example provided can be generated.
这个C++源代码文件 `float_rounded_rect.cc` 定义了 `blink::FloatRoundedRect` 类，用于表示带圆角的浮点数矩形。它属于 Chromium Blink 渲染引擎的一部分，负责处理网页元素的几何形状，特别是那些具有圆角边框的元素。

以下是该文件的主要功能：

**1. 表示带圆角的矩形:**

*   `FloatRoundedRect` 类存储了一个矩形 (`rect_`) 和四个角的半径 (`radii_`) 信息。
*   可以方便地表示各种具有不同圆角半径的矩形，包括所有角都相同、部分角有圆角、甚至没有圆角的矩形。

**2. 多种构造方式:**

*   提供了多种构造函数，允许从不同的输入创建 `FloatRoundedRect` 对象：
    *   直接指定矩形的左上角坐标、宽度和高度。
    *   使用 `gfx::RectF` (浮点数矩形) 和 `Radii` (角半径) 对象。
    *   使用 `gfx::Rect` (整数矩形) 和 `Radii` 对象。
    *   分别指定每个角的半径大小。
    *   从 `gfx::RRectF` (图形库的圆角矩形) 对象转换。

**3. 角半径管理 (`Radii` 内部类):**

*   内部的 `Radii` 结构体专门用于管理四个角的半径。
*   提供了设置最小半径、判断是否所有角半径都相同、缩放半径、以及外扩半径的方法。
*   `Outset` 方法用于向外扩展半径。
*   `OutsetForMarginOrShadow` 和 `OutsetForShapeMargin` 方法针对 CSS 的 `margin`、`box-shadow` 和 `shape-margin` 属性提供了特定的半径外扩逻辑。

**4. 几何计算:**

*   `XInterceptsAtY`: 计算在给定的 Y 坐标处，圆角矩形与垂直线的交点的 X 坐标范围。这对于命中测试和区域判断非常有用。
*   `Outset`:  扩展整个圆角矩形的大小。
*   `OutsetForMarginOrShadow`: 根据 `margin` 或 `box-shadow` 的值扩展圆角矩形，同时考虑圆角半径对扩展的影响（根据 CSS 规范）。
*   `OutsetForShapeMargin`:  根据 CSS 的 `shape-margin` 属性扩展圆角矩形。
*   `IntersectsQuad`: 判断圆角矩形是否与给定的四边形相交。这在处理复杂图形的碰撞检测时非常重要。

**5. 半径约束和渲染:**

*   `ConstrainRadii`: 确保角半径不会过大，导致在矩形内部“折叠”或渲染异常。它会根据矩形的尺寸缩放半径。
*   `IsRenderable`: 检查圆角矩形是否可以正常渲染，即半径是否在合理范围内。

**6. 调试和输出:**

*   提供了 `ToString` 方法，用于将 `FloatRoundedRect` 和 `Radii` 对象转换为字符串表示，方便调试。
*   重载了 `<<` 运算符，可以直接将 `FloatRoundedRect` 对象输出到 `std::ostream`。

**与 JavaScript, HTML, CSS 的关系：**

`FloatRoundedRect` 类是 Blink 渲染引擎内部处理元素几何形状的关键部分，它直接参与了网页元素的渲染过程，因此与 JavaScript, HTML, CSS 有着密切的关系。

*   **CSS `border-radius`:**  这是最直接的关系。当 CSS 样式中设置了 `border-radius` 属性时，渲染引擎会解析这些值，并最终使用 `FloatRoundedRect` 类来表示元素的形状。`Radii` 结构体直接对应了 CSS 中四个角的半径设置。

    *   **示例:**  在 CSS 中设置 `border-radius: 10px;` 会导致浏览器内部创建一个 `FloatRoundedRect` 对象，其四个角的半径均为 10px。`border-radius: 10px 20px;` 会影响 `top-left` 和 `bottom-right` 以及 `top-right` 和 `bottom-left` 的半径。 `border-radius: 10px 20px 30px 40px;` 则分别对应 `top-left`, `top-right`, `bottom-right`, `bottom-left` 的半径。

*   **CSS `margin` 和 `box-shadow`:**  `OutsetForMarginOrShadow` 方法的存在表明，`FloatRoundedRect` 类考虑了 `margin` 和 `box-shadow` 对元素形状的影响。当元素有 `margin` 或 `box-shadow` 时，渲染引擎会使用这个方法来计算包含 `margin` 或阴影的更大的圆角矩形区域。

    *   **示例:** 如果一个元素的 `border-radius` 为 5px，且 `margin` 为 10px，那么在进行某些布局或碰撞检测时，引擎可能会使用一个通过 `OutsetForMarginOrShadow` 计算出的更大的圆角矩形。

*   **CSS `shape-margin`:** `OutsetForShapeMargin` 方法用于处理 CSS 的 `shape-margin` 属性，该属性定义了浮动元素周围形状的边距。`FloatRoundedRect` 可以根据 `shape-margin` 的值进行扩展，以正确表示浮动元素的形状。

    *   **示例:**  当一个浮动元素设置了 `shape-outside` 和 `shape-margin` 时，`FloatRoundedRect` 会被用来描述该元素的形状，并考虑 `shape-margin` 增加的空白区域。

*   **JavaScript (通过 DOM API):**  虽然 JavaScript 代码不会直接操作 `FloatRoundedRect` 对象，但 JavaScript 可以通过 DOM API 修改元素的 CSS 样式（包括 `border-radius`、`margin`、`box-shadow` 等）。这些修改会触发渲染引擎的重新布局和重绘，最终导致创建或更新相应的 `FloatRoundedRect` 对象。

    *   **示例:**  JavaScript 代码 `element.style.borderRadius = '20px';` 会导致浏览器更新元素的渲染表示，其中就可能包括更新 `FloatRoundedRect` 对象的角半径。

*   **HTML:** HTML 定义了网页的结构，而 CSS 负责样式。`FloatRoundedRect` 最终是为了渲染 HTML 元素而存在的。HTML 元素的几何属性（如尺寸和位置）会影响 `FloatRoundedRect` 对象的创建和属性。

**逻辑推理的假设输入与输出：**

**假设输入 1:**

*   创建一个 `FloatRoundedRect` 对象，矩形为 `(10, 20, 100, 50)`，四个角半径都为 `10px`。

**输出 1:**

*   `rect_` 将是 `gfx::RectF(10, 20, 100, 50)`。
*   `radii_` 的 `top_left_`, `top_right_`, `bottom_left_`, `bottom_right_` 的宽度和高度都将是 `10px`。

**假设输入 2:**

*   对一个矩形为 `(0, 0, 100, 100)`，左上角半径为 `(20, 10)`，其他角半径为 `0` 的 `FloatRoundedRect` 对象调用 `XInterceptsAtY(10, min_x, max_x)`。

**输出 2:**

*   由于 Y 坐标 10 位于左上角的圆角区域内，`min_x` 将会大于 0，`max_x` 将会等于 100。具体的 `min_x` 值需要根据圆的方程计算，大概会在 20 附近。

**假设输入 3:**

*   一个 `FloatRoundedRect` 对象的矩形为 `(0, 0, 50, 50)`，四个角半径都为 `30px`。调用 `ConstrainRadii()`。

**输出 3:**

*   由于水平方向的半径之和 (30 + 30 = 60) 大于矩形的宽度 (50)，垂直方向的半径之和也大于矩形的高度，`ConstrainRadii()` 会缩小半径。缩放因子将是 `min(50/60, 50/60) = 5/6`。
*   调整后的半径大约为 `30 * (5/6) = 25px`。

**用户或编程常见的使用错误：**

1. **半径过大导致渲染问题：**  如果设置的 `border-radius` 值过大，超过了元素尺寸的一半，会导致角重叠，渲染出不期望的形状。`ConstrainRadii()` 的作用就是避免这种情况。

    *   **示例:**  一个 `50px * 50px` 的 div，设置 `border-radius: 100px;`，可能会导致渲染出现问题，或者被浏览器自动约束。

2. **误解 `shape-margin` 的作用范围:** `shape-margin` 只影响浮动元素周围的形状边距，不会改变元素自身的尺寸或边框半径。

    *   **示例:**  即使设置了很大的 `shape-margin`，元素的实际 `border-radius` 仍然是由 `border-radius` 属性决定的。

3. **在 JavaScript 中直接操作渲染对象：**  开发者不应该直接尝试创建或修改 Blink 内部的 `FloatRoundedRect` 对象。应该通过操作 DOM 元素的 CSS 属性来实现所需的视觉效果。直接操作渲染引擎的内部对象可能会导致不可预测的行为和错误。

4. **忽略半径约束：**  在某些自定义渲染逻辑中，如果开发者没有像 Blink 那样进行半径约束，可能会出现视觉上的错误，例如圆角“溢出”到矩形内部。

总而言之，`blink/renderer/platform/geometry/float_rounded_rect.cc` 文件定义了一个核心的数据结构和相关方法，用于在 Chromium Blink 渲染引擎中精确表示和操作带圆角的矩形，这对于实现网页元素的视觉效果至关重要，并直接关联到 CSS 的边框和布局属性。

### 提示词
```
这是目录为blink/renderer/platform/geometry/float_rounded_rect.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2013 Adobe Systems Incorporated. All rights reserved.
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

#include "third_party/blink/renderer/platform/geometry/float_rounded_rect.h"

#include <algorithm>
#include <cmath>

#include "third_party/blink/renderer/platform/geometry/infinite_int_rect.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "ui/gfx/geometry/insets_f.h"
#include "ui/gfx/geometry/quad_f.h"

namespace blink {

FloatRoundedRect::FloatRoundedRect(float x, float y, float width, float height)
    : rect_(x, y, width, height) {}

FloatRoundedRect::FloatRoundedRect(const gfx::RectF& rect, const Radii& radii)
    : rect_(rect), radii_(radii) {}

FloatRoundedRect::FloatRoundedRect(const gfx::Rect& rect, const Radii& radii)
    : rect_(rect), radii_(radii) {}

FloatRoundedRect::FloatRoundedRect(const gfx::RectF& rect,
                                   const gfx::SizeF& top_left,
                                   const gfx::SizeF& top_right,
                                   const gfx::SizeF& bottom_left,
                                   const gfx::SizeF& bottom_right)
    : rect_(rect), radii_(top_left, top_right, bottom_left, bottom_right) {}

FloatRoundedRect::FloatRoundedRect(const gfx::RRectF& r)
    : FloatRoundedRect(r.rect()) {
  gfx::Vector2dF top_left = r.GetCornerRadii(gfx::RRectF::Corner::kUpperLeft);
  gfx::Vector2dF top_right = r.GetCornerRadii(gfx::RRectF::Corner::kUpperRight);
  gfx::Vector2dF bottom_left =
      r.GetCornerRadii(gfx::RRectF::Corner::kLowerLeft);
  gfx::Vector2dF bottom_right =
      r.GetCornerRadii(gfx::RRectF::Corner::kLowerRight);
  SetRadii(Radii(gfx::SizeF(top_left.x(), top_left.y()),
                 gfx::SizeF(top_right.x(), top_right.y()),
                 gfx::SizeF(bottom_left.x(), bottom_left.y()),
                 gfx::SizeF(bottom_right.x(), bottom_right.y())));
}

void FloatRoundedRect::Radii::SetMinimumRadius(float minimum_radius) {
  top_left_.set_width(std::max(minimum_radius, top_left_.width()));
  top_left_.set_height(std::max(minimum_radius, top_left_.height()));
  top_right_.set_width(std::max(minimum_radius, top_right_.width()));
  top_right_.set_height(std::max(minimum_radius, top_right_.height()));
  bottom_left_.set_width(std::max(minimum_radius, bottom_left_.width()));
  bottom_left_.set_height(std::max(minimum_radius, bottom_left_.height()));
  bottom_right_.set_width(std::max(minimum_radius, bottom_right_.width()));
  bottom_right_.set_height(std::max(minimum_radius, bottom_right_.height()));
}

std::optional<float> FloatRoundedRect::Radii::UniformRadius() const {
  if (top_left_.width() == top_left_.height() && top_left_ == top_right_ &&
      top_left_ == bottom_left_ && top_left_ == bottom_right_) {
    return top_left_.width();
  }
  return std::nullopt;
}

void FloatRoundedRect::Radii::Scale(float factor) {
  if (factor == 1)
    return;

  // If either radius on a corner becomes zero, reset both radii on that corner.
  top_left_.Scale(factor);
  if (!top_left_.width() || !top_left_.height())
    top_left_ = gfx::SizeF();
  top_right_.Scale(factor);
  if (!top_right_.width() || !top_right_.height())
    top_right_ = gfx::SizeF();
  bottom_left_.Scale(factor);
  if (!bottom_left_.width() || !bottom_left_.height())
    bottom_left_ = gfx::SizeF();
  bottom_right_.Scale(factor);
  if (!bottom_right_.width() || !bottom_right_.height())
    bottom_right_ = gfx::SizeF();
}

void FloatRoundedRect::Radii::Outset(const gfx::OutsetsF& outsets) {
  if (top_left_.width() > 0)
    top_left_.set_width(top_left_.width() + outsets.left());
  if (top_left_.height() > 0)
    top_left_.set_height(top_left_.height() + outsets.top());
  if (top_right_.width() > 0)
    top_right_.set_width(top_right_.width() + outsets.right());
  if (top_right_.height() > 0)
    top_right_.set_height(top_right_.height() + outsets.top());
  if (bottom_left_.width() > 0)
    bottom_left_.set_width(bottom_left_.width() + outsets.left());
  if (bottom_left_.height() > 0)
    bottom_left_.set_height(bottom_left_.height() + outsets.bottom());
  if (bottom_right_.width() > 0)
    bottom_right_.set_width(bottom_right_.width() + outsets.right());
  if (bottom_right_.height() > 0)
    bottom_right_.set_height(bottom_right_.height() + outsets.bottom());
}

// From: https://drafts.csswg.org/css-backgrounds-3/#corner-shaping
// ... in order to create a sharper corner when the border radius is small (and
// thus ensure continuity between round and sharp corners), when the border
// radius is less than the margin, the margin is multiplied by the proportion
// 1 + (r-1)^3, where r is the ratio of the border radius to the margin, in
// calculating the corner radii of the margin box shape.
// And https://drafts.csswg.org/css-backgrounds-3/#shadow-shape:
// ... For example, if the border radius is 10px and the spread distance is
// 20px (r = .5), the corner radius of the shadow shape will be
// 10px + 20px × (1 + (.5 - 1)^3) = 27.5px rather than 30px. This adjustment
// is applied independently to the radii in each dimension.
static void OutsetCornerForMarginOrShadow(gfx::SizeF& corner,
                                          float width_outset,
                                          float height_outset) {
  if (corner.IsZero() || (width_outset == 0 && height_outset == 0))
    return;

  float width_factor = 1;
  if (corner.width() < std::abs(width_outset)) {
    width_factor = 1 + std::pow(corner.width() / std::abs(width_outset) - 1, 3);
  }

  float height_factor = 1;
  if (corner.height() == corner.width() && width_outset == height_outset) {
    height_factor = width_factor;
  } else if (corner.height() < std::abs(height_outset)) {
    height_factor =
        1 + std::pow(corner.height() / std::abs(height_outset) - 1, 3);
  }

  corner.set_width(std::max(corner.width() + width_factor * width_outset, 0.f));
  corner.set_height(
      std::max(corner.height() + height_factor * height_outset, 0.f));
}

void FloatRoundedRect::Radii::OutsetForMarginOrShadow(
    const gfx::OutsetsF& outsets) {
  OutsetCornerForMarginOrShadow(top_left_, outsets.left(), outsets.top());
  OutsetCornerForMarginOrShadow(top_right_, outsets.right(), outsets.top());
  OutsetCornerForMarginOrShadow(bottom_left_, outsets.left(), outsets.bottom());
  OutsetCornerForMarginOrShadow(bottom_right_, outsets.right(),
                                outsets.bottom());
}

void FloatRoundedRect::Radii::OutsetForShapeMargin(float outset) {
  // TODO(crbug.com/1309478): This isn't correct for non-circular
  // corners (that is, corners that have x and y radii that are not
  // equal).  But it's not clear to me if the correct result for that
  // case is even an ellipse.
  gfx::SizeF outset_size(outset, outset);
  top_left_ += outset_size;
  top_right_ += outset_size;
  bottom_left_ += outset_size;
  bottom_right_ += outset_size;
}

static inline float CornerRectIntercept(float y,
                                        const gfx::RectF& corner_rect) {
  DCHECK_GT(corner_rect.height(), 0);
  return corner_rect.width() *
         sqrt(1 - (y * y) / (corner_rect.height() * corner_rect.height()));
}

bool FloatRoundedRect::XInterceptsAtY(float y,
                                      float& min_x_intercept,
                                      float& max_x_intercept) const {
  if (y < Rect().y() || y > Rect().bottom())
    return false;

  if (!IsRounded()) {
    min_x_intercept = Rect().x();
    max_x_intercept = Rect().right();
    return true;
  }

  const gfx::RectF& top_left_rect = TopLeftCorner();
  const gfx::RectF& bottom_left_rect = BottomLeftCorner();

  if (!top_left_rect.IsEmpty() && y >= top_left_rect.y() &&
      y < top_left_rect.bottom()) {
    min_x_intercept =
        top_left_rect.right() -
        CornerRectIntercept(top_left_rect.bottom() - y, top_left_rect);
  } else if (!bottom_left_rect.IsEmpty() && y >= bottom_left_rect.y() &&
             y <= bottom_left_rect.bottom()) {
    min_x_intercept =
        bottom_left_rect.right() -
        CornerRectIntercept(y - bottom_left_rect.y(), bottom_left_rect);
  } else {
    min_x_intercept = rect_.x();
  }

  const gfx::RectF& top_right_rect = TopRightCorner();
  const gfx::RectF& bottom_right_rect = BottomRightCorner();

  if (!top_right_rect.IsEmpty() && y >= top_right_rect.y() &&
      y <= top_right_rect.bottom()) {
    max_x_intercept =
        top_right_rect.x() +
        CornerRectIntercept(top_right_rect.bottom() - y, top_right_rect);
  } else if (!bottom_right_rect.IsEmpty() && y >= bottom_right_rect.y() &&
             y <= bottom_right_rect.bottom()) {
    max_x_intercept =
        bottom_right_rect.x() +
        CornerRectIntercept(y - bottom_right_rect.y(), bottom_right_rect);
  } else {
    max_x_intercept = rect_.right();
  }

  return true;
}

void FloatRoundedRect::Outset(const gfx::OutsetsF& outsets) {
  rect_.Outset(outsets);
  radii_.Outset(outsets);
}

void FloatRoundedRect::OutsetForMarginOrShadow(const gfx::OutsetsF& outsets) {
  if (outsets.IsEmpty())
    return;
  rect_.Outset(outsets);
  radii_.OutsetForMarginOrShadow(outsets);
}

void FloatRoundedRect::OutsetForShapeMargin(float outset) {
  DCHECK_GE(outset, 0);
  if (outset == 0.f)
    return;
  rect_.Outset(outset);
  radii_.OutsetForShapeMargin(outset);
}

bool FloatRoundedRect::IntersectsQuad(const gfx::QuadF& quad) const {
  if (!quad.IntersectsRect(rect_))
    return false;

  const auto [quad_min, quad_max] = quad.Extents();

  // For each corner, first check the remaining (two) separating axes of the
  // rectangle that encloses the corner. The other (two) axes coincide with the
  // axes of `rect_`. If none of those are separating, proceed to call
  // IntersectsRectPartial to check the potential axes of `quad`.

  if (!radii_.TopLeft().IsEmpty()) {
    const gfx::RectF corner_rect(TopLeftCorner());
    if (quad_min.y() <= corner_rect.bottom() &&
        quad_min.x() <= corner_rect.right() &&
        quad.IntersectsRectPartial(corner_rect)) {
      if (!quad.IntersectsEllipse(corner_rect.bottom_right(),
                                  corner_rect.size())) {
        return false;
      }
    }
  }

  if (!radii_.TopRight().IsEmpty()) {
    const gfx::RectF corner_rect(TopRightCorner());
    if (quad_min.y() <= corner_rect.bottom() &&
        quad_max.x() >= corner_rect.x() &&
        quad.IntersectsRectPartial(corner_rect)) {
      if (!quad.IntersectsEllipse(corner_rect.bottom_left(),
                                  corner_rect.size())) {
        return false;
      }
    }
  }

  if (!radii_.BottomLeft().IsEmpty()) {
    const gfx::RectF corner_rect(BottomLeftCorner());
    if (quad_max.y() >= corner_rect.y() &&
        quad_min.x() <= corner_rect.right() &&
        quad.IntersectsRectPartial(corner_rect)) {
      if (!quad.IntersectsEllipse(corner_rect.top_right(),
                                  corner_rect.size())) {
        return false;
      }
    }
  }

  if (!radii_.BottomRight().IsEmpty()) {
    const gfx::RectF corner_rect(BottomRightCorner());
    if (quad_max.y() >= corner_rect.y() && quad_max.x() >= corner_rect.x() &&
        quad.IntersectsRectPartial(corner_rect)) {
      if (!quad.IntersectsEllipse(corner_rect.origin(), corner_rect.size())) {
        return false;
      }
    }
  }

  return true;
}

void FloatRoundedRect::ConstrainRadii() {
  float factor = 1;

  float horizontal_sum =
      std::max(radii_.TopLeft().width() + radii_.TopRight().width(),
               radii_.BottomLeft().width() + radii_.BottomRight().width());
  if (horizontal_sum > rect_.width())
    factor = std::min(rect_.width() / horizontal_sum, factor);

  float vertical_sum =
      std::max(radii_.TopLeft().height() + radii_.BottomLeft().height(),
               radii_.TopRight().height() + radii_.BottomRight().height());
  if (vertical_sum > rect_.height())
    factor = std::min(rect_.height() / vertical_sum, factor);

  DCHECK_LE(factor, 1);
  radii_.Scale(factor);
  DCHECK(IsRenderable());
}

bool FloatRoundedRect::IsRenderable() const {
  constexpr float kTolerance = 1.0001;
  return radii_.TopLeft().width() + radii_.TopRight().width() <=
             rect_.width() * kTolerance &&
         radii_.BottomLeft().width() + radii_.BottomRight().width() <=
             rect_.width() * kTolerance &&
         radii_.TopLeft().height() + radii_.BottomLeft().height() <=
             rect_.height() * kTolerance &&
         radii_.TopRight().height() + radii_.BottomRight().height() <=
             rect_.height() * kTolerance;
}

std::ostream& operator<<(std::ostream& ostream, const FloatRoundedRect& rect) {
  return ostream << rect.ToString();
}

std::ostream& operator<<(std::ostream& ostream,
                         const FloatRoundedRect::Radii& radii) {
  return ostream << radii.ToString();
}

String FloatRoundedRect::Radii::ToString() const {
  return String::Format(
      "tl:%s; tr:%s; bl:%s; br:%s", TopLeft().ToString().c_str(),
      TopRight().ToString().c_str(), BottomLeft().ToString().c_str(),
      BottomRight().ToString().c_str());
}

String FloatRoundedRect::ToString() const {
  if (Rect() == gfx::RectF(InfiniteIntRect())) {
    return "InfiniteIntRect";
  }
  if (GetRadii().IsZero())
    return String(Rect().ToString());
  return String(Rect().ToString()) + " radii:(" + GetRadii().ToString() + ")";
}

}  // namespace blink
```