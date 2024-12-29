Response:
Let's break down the thought process for analyzing this C++ code and answering the prompt.

**1. Understanding the Goal:**

The core request is to understand the functionality of `nine_piece_image_grid.cc`, its relation to web technologies, and potential usage/debugging scenarios. This requires a combination of code analysis and knowledge of CSS border-image properties.

**2. Initial Code Scan and Keyword Recognition:**

My first step is to quickly scan the code for recognizable keywords and patterns. I immediately notice:

* **`NinePieceImageGrid`:** This is the central class, suggesting it handles a nine-part image structure.
* **`border-image` terms:**  `border_slice`, `border_widths`, `BorderImageLength`, `BorderImageLengthBox`. This strongly hints at the CSS `border-image` property.
* **`LayoutUnit`, `gfx::Rect`, `gfx::SizeF`, `gfx::Outsets`:** These are geometry and layout-related types, confirming its role in rendering.
* **`ComputeEdgeWidth`, `ComputeEdgeSlice`, `SnapEdgeWidths`:** These functions point towards calculating and adjusting the sizes of the nine image pieces.
* **`SetDrawInfoCorner`, `SetDrawInfoEdge`, `SetDrawInfoMiddle`:**  These suggest the code prepares information for drawing the individual pieces.
* **`ENinePieceImageRule`:** This enum likely represents the `border-image-repeat` values (stretch, repeat, round).
* **`slice_scale`, `zoom`:** These relate to image scaling and zoom levels.
* **`fill_`:** This probably corresponds to the `border-image-fill` property.

**3. Connecting to Web Technologies:**

Based on the keywords, the connection to CSS `border-image` becomes clear. I can now start mapping the C++ concepts to their CSS counterparts:

* **`NinePieceImageGrid`:**  Represents the entire concept of a `border-image`.
* **`border_slice`:**  Corresponds to the `border-image-slice` property.
* **`border_widths`:** Relates to the `border-width` property (and potentially influences `border-image-width`).
* **`horizontal_tile_rule_`, `vertical_tile_rule_`:**  Map to the `border-image-repeat` property.
* **`fill_`:** Corresponds to the `border-image-fill` property.
* **The nine pieces (corners, edges, middle):** Directly represent the visual structure defined by `border-image`.

**4. Functionality Breakdown:**

Now, I analyze the key functions:

* **`ComputeEdgeWidth`:**  Calculates the width of the border image edges, considering `border-image-width` values (number, length, auto). It needs to handle units and scaling.
* **`ComputeEdgeSlice`:**  Determines the size of the slices from the source image, accounting for percentages and scaling.
* **`SnapEdgeWidths`:**  This is interesting. It deals with rounding the edge widths and handling cases where edges might abut (touch). This likely aims to prevent gaps or overlaps between the pieces.
* **Constructor (`NinePieceImageGrid(...)`):**  This is where the core calculations happen. It takes the input parameters (image data, sizes, scales, etc.) and initializes the internal state of the `NinePieceImageGrid` object. The logic for resolving `border-image-width: auto` and the scaling factor `f` is important here.
* **`SetDrawInfoCorner`, `SetDrawInfoEdge`, `SetDrawInfoMiddle`:** These functions prepare the drawing information for each of the nine pieces, including source and destination rectangles, and tiling rules.

**5. JavaScript/HTML/CSS Relationship:**

The C++ code itself doesn't directly interact with JavaScript or HTML. However, it's crucial for *rendering* the effects of CSS properties defined in stylesheets or inline styles applied to HTML elements. The browser's rendering engine (Blink in this case) parses the CSS, and when it encounters `border-image`, it uses classes like `NinePieceImageGrid` to implement the visual representation.

**6. Logical Reasoning (Input/Output):**

To illustrate the logic, I need to consider the inputs to the `NinePieceImageGrid` constructor and what it produces.

* **Input:**  Think about the parameters: the image source, the `border-image-slice` values, `border-image-width`, the element's box size, and any scaling or zoom factors.
* **Output:** The primary output is the set of `NinePieceDrawInfo` structures, each containing the source and destination rectangles and tiling rules needed to draw one of the nine pieces.

**7. Common Usage Errors:**

Considering how developers use `border-image`, I can identify potential pitfalls:

* **Incorrect `border-image-slice` values:**  Slicing the image in a way that leaves no content for certain pieces.
* **Mismatched `border-image-width`:** Specifying widths that are larger than the available space, leading to unexpected scaling.
* **Forgetting `border-image-source`:**  The image is missing.
* **Incorrect units in `border-image-slice` or `border-image-width`:** Using `px` when percentages or unitless numbers are expected.
* **Not understanding `border-image-repeat`:**  Unexpected tiling patterns.

**8. Debugging Clues (User Operations):**

To trace how the code is reached during debugging, I consider the user actions that trigger `border-image` rendering:

* **Page load:**  The browser parses the CSS and renders elements with `border-image`.
* **Dynamic CSS changes:** JavaScript might modify the `border-image` properties, causing a re-render.
* **Resizing the browser window:**  The layout changes, potentially affecting `border-image` rendering.
* **Zooming in/out:**  The `zoom` factor passed to `NinePieceImageGrid` will be different.

**9. Structuring the Answer:**

Finally, I organize the information into clear sections, addressing each part of the prompt. I use examples to illustrate the connection to web technologies and the consequences of common errors. I also focus on providing concrete debugging steps.

This systematic approach—from initial code scan and keyword recognition to detailed analysis and connection with web concepts—allows me to effectively understand and explain the functionality of the given C++ code.
这个C++源代码文件 `nine_piece_image_grid.cc` 属于 Chromium Blink 渲染引擎的一部分，它的核心功能是**处理和计算如何绘制使用 CSS `border-image` 属性的元素**。

具体来说，它实现了将一个图片分割成九个部分（四个角，四个边，以及中间部分），并根据 `border-image` 的各种属性（如 `border-image-source`, `border-image-slice`, `border-image-width`, `border-image-repeat`, `border-image-outset`, `border-image-fill`）来确定如何绘制这些部分，从而创建一个具有自定义边框的元素。

以下是该文件功能的详细说明：

**1. 计算切片 (Slicing):**

* **`ComputeEdgeSlice` 函数:**  计算图片四个边的切片大小。`border-image-slice` 属性定义了如何将源图像切分为九个区域。这个函数会根据 `border-image-slice` 的值（可以是像素值或百分比）以及图片的实际尺寸来计算切片的具体大小。
    * **假设输入:**  一个图片的宽度为 100px，`border-image-slice: 10px 20%`。
    * **输出:** 左边切片为 10px，右边切片为 20px (100px 的 20%)。

**2. 计算边框宽度 (Widths):**

* **`ComputeEdgeWidth` 函数:** 计算边框四个边的宽度。`border-image-width` 属性定义了边框图像的宽度。这个函数会根据 `border-image-width` 的值（可以是像素值、`auto` 或相对于元素尺寸的长度值）以及图片的切片大小来计算边框的实际宽度。
    * **`auto` 的处理:** 如果 `border-image-width` 设置为 `auto`，则边框宽度将等于图片对应边的切片大小。
    * **长度值的处理:** 如果是长度值，则会将其转换为实际的像素值。
    * **假设输入:**  一个图片的左边切片大小为 20px，`border-image-width: auto`。
    * **输出:** 左边框的宽度为 20px。
    * **假设输入:**  一个容器的宽度为 200px，图片的左边切片大小为 20px，`border-image-width: 10%`。
    * **输出:** 左边框的宽度为 20px (200px 的 10%)。

**3. 对齐边框宽度 (Snapping):**

* **`SnapEdgeWidths` 函数:**  对计算出的边框宽度进行微调，以确保边框的绘制是平滑的，并且避免出现像素级别的间隙或重叠。它会考虑元素盒子的尺寸，并尝试将边框宽度对齐到像素边界。

**4. `NinePieceImageGrid` 类:**

* **构造函数:** 接收 `NinePieceImage` 对象（包含切片信息、平铺规则等）、图片尺寸、缩放比例、边框图像区域、边框宽度等信息，并根据这些信息计算出九个部分各自的绘制信息（源图像的哪个区域，目标绘制到元素的哪个区域）。
* **`SetDrawInfoCorner`, `SetDrawInfoEdge`, `SetDrawInfoMiddle` 函数:**  分别计算并设置九个部分（四个角、四个边、中间部分）的绘制信息，包括源图像的矩形区域和目标绘制的矩形区域。
* **`GetNinePieceDrawInfo` 函数:**  根据传入的 `NinePiece` 枚举值（表示九个部分中的哪一个），返回对应的绘制信息。

**与 JavaScript, HTML, CSS 的关系：**

这个 C++ 文件是浏览器渲染引擎内部实现的一部分，它直接响应 CSS 的 `border-image` 属性。

* **CSS `border-image-source`:**  指定要使用的图片。
* **CSS `border-image-slice`:**  决定了如何切割图片。例如，`border-image-slice: 10px 20px 30px 40px` 将图片从上、右、下、左四个方向分别切割 10px、20px、30px 和 40px。
* **CSS `border-image-width`:**  指定边框的宽度。例如，`border-image-width: 5px` 或 `border-image-width: auto` 或 `border-image-width: 10%`。
* **CSS `border-image-repeat`:**  指定如何平铺边框的边缘和中间部分。例如，`border-image-repeat: stretch` (拉伸), `repeat` (重复), `round` (缩放重复)。对应代码中的 `horizontal_tile_rule_` 和 `vertical_tile_rule_`。
* **CSS `border-image-outset`:**  指定边框图像超出边框盒子的距离。
* **CSS `border-image-fill`:**  指定是否填充中间区域。对应代码中的 `fill_`。

当浏览器解析到包含 `border-image` 属性的 CSS 规则时，渲染引擎会使用 `NinePieceImageGrid` 类来计算如何绘制这个边框。

**举例说明:**

假设有以下 HTML 和 CSS：

```html
<div class="bordered"></div>
```

```css
.bordered {
  width: 200px;
  height: 100px;
  border: 10px solid transparent; /* 需要设置边框，但颜色可以透明 */
  border-image-source: url("border.png");
  border-image-slice: 20 30 20 30 fill;
  border-image-width: 10px;
  border-image-repeat: round;
}
```

当浏览器渲染这个 `div` 元素时，`nine_piece_image_grid.cc` 文件中的代码会执行以下操作：

1. **读取 CSS 属性:**  获取 `border-image-source` 指向的图片，以及 `border-image-slice`, `border-image-width`, `border-image-repeat` 的值。
2. **计算切片:**  `ComputeEdgeSlice` 会根据 `border-image-slice: 20 30 20 30` 和图片尺寸计算出上、右、下、左的切片大小。`fill` 关键字表示中间部分也要绘制。
3. **计算边框宽度:** `ComputeEdgeWidth` 会根据 `border-image-width: 10px` 计算出边框的宽度。
4. **创建 `NinePieceImageGrid` 对象:**  使用上述信息创建 `NinePieceImageGrid` 对象。
5. **计算绘制信息:** `SetDrawInfoCorner`, `SetDrawInfoEdge`, `SetDrawInfoMiddle` 等函数会计算出九个部分各自在源图片中的位置和目标元素中的位置，以及平铺规则。
6. **绘制:**  渲染引擎最终会根据这些绘制信息，将图片的不同部分绘制到 `div` 元素的边框区域，实现自定义的边框效果。

**逻辑推理 (假设输入与输出):**

假设我们有一个 100x100 的图片 `border.png`，并且有以下 CSS：

```css
.element {
  width: 150px;
  height: 80px;
  border: 5px solid transparent;
  border-image-source: url("border.png");
  border-image-slice: 10 20 10 20;
  border-image-width: auto;
}
```

* **假设输入:**
    * 图片尺寸: 100x100
    * `border-image-slice`: 上10px, 右20px, 下10px, 左20px
    * 元素尺寸: 150px x 80px
    * `border-image-width`: auto

* **输出 (部分):**
    * **左上角 (kTopLeftPiece):**
        * 源图像区域: x:0, y:0, width:20px, height:10px
        * 目标区域: x:0, y:0, width:20px, height:10px (因为 `border-image-width: auto`，所以边框宽度等于切片大小)
    * **顶部边缘 (kTopPiece):**
        * 源图像区域: x:20px, y:0, width:60px (100 - 20 - 20), height:10px
        * 目标区域: x:20px, y:0, width:110px (150 - 20 - 20), height:10px
        * 平铺规则: `kStretchImageRule` (默认行为)

**用户或编程常见的使用错误:**

1. **`border-image-source` 路径错误:**  如果图片路径不正确，边框图像将无法加载，导致边框显示异常。
2. **`border-image-slice` 的值超出范围:** 如果切片的值大于图片的尺寸，可能会导致意想不到的裁剪或无法显示。
3. **`border-image-width` 设置不当:**
    * 设置为 0 或负数可能导致边框消失。
    * 设置为过大的值可能导致边框覆盖内容。
4. **忘记设置 `border` 属性:** 虽然 `border-image` 可以替换元素的边框样式，但仍然需要设置 `border` 属性来定义边框的基本宽度，`border-image-width: auto` 会参考这个宽度。如果 `border` 宽度为 0，则 `auto` 可能解析为 0。
5. **对 `border-image-repeat` 的理解偏差:**  不理解 `stretch`, `repeat`, `round` 的区别，导致平铺效果不符合预期。
6. **混合使用单位时出错:** 例如，`border-image-slice` 使用像素，而 `border-image-width` 使用百分比，可能会导致计算混乱。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在 HTML 文件中添加一个元素。**
2. **用户在 CSS 文件中为该元素设置了 `border-image` 相关的属性。**
3. **浏览器开始解析 HTML 和 CSS。**
4. **当渲染引擎遇到设置了 `border-image` 的元素时，它会创建一个 `NinePieceImageGrid` 对象。**
5. **渲染引擎会从 CSSOM (CSS Object Model) 中获取 `border-image` 的属性值。**
6. **`ComputeEdgeSlice` 和 `ComputeEdgeWidth` 等函数会被调用，根据 CSS 属性值和图片尺寸计算切片大小和边框宽度。**
7. **`SetDrawInfoCorner`、`SetDrawInfoEdge`、`SetDrawInfoMiddle` 等函数会被调用，计算出九个部分的绘制信息。**
8. **最终，这些绘制信息会被传递给底层的绘图 API，将边框图像绘制到屏幕上。**

**调试线索:**

* 如果边框图像没有显示，检查 `border-image-source` 的路径是否正确，以及图片是否可以被浏览器访问。
* 如果边框的切割不正确，检查 `border-image-slice` 的值是否符合预期。可以使用浏览器的开发者工具查看元素的计算样式，确认 `border-image-slice` 的解析结果。
* 如果边框的宽度不正确，检查 `border-image-width` 的设置，以及是否正确理解了 `auto` 的含义。
* 如果边框的平铺效果不正确，检查 `border-image-repeat` 的设置。
* 使用浏览器的开发者工具（如 Chrome DevTools）的 "Elements" 面板，可以查看元素的计算样式，包括 `border-image` 的各个属性的解析值，这有助于理解渲染引擎是如何解释这些 CSS 属性的。
* 在 Blink 渲染引擎的源代码中设置断点，可以跟踪 `NinePieceImageGrid` 对象的创建和相关函数的调用，深入了解计算过程。

总而言之，`nine_piece_image_grid.cc` 文件在 Chromium Blink 引擎中扮演着关键的角色，它负责将 CSS 的 `border-image` 属性转化为实际的图形绘制操作，使得开发者能够创建出具有高度自定义外观的元素边框。

Prompt: 
```
这是目录为blink/renderer/core/paint/nine_piece_image_grid.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/nine_piece_image_grid.h"

#include "third_party/blink/renderer/core/layout/geometry/box_strut.h"
#include "third_party/blink/renderer/platform/geometry/length_functions.h"
#include "ui/gfx/geometry/outsets.h"

namespace blink {

namespace {

LayoutUnit ComputeEdgeWidth(const BorderImageLength& border_slice,
                            int border_side,
                            float image_side,
                            int box_extent) {
  if (border_slice.IsNumber())
    return LayoutUnit(border_slice.Number() * border_side);
  if (border_slice.length().IsAuto())
    return LayoutUnit(image_side);
  return ValueForLength(border_slice.length(), LayoutUnit(box_extent));
}

float ComputeEdgeSlice(const Length& slice, float slice_scale, float maximum) {
  float resolved;
  // If the slice is a <number> (stored as a fixed Length), scale it by the
  // slice scale to get to the same space as the image.
  if (slice.IsFixed()) {
    resolved = slice.Value() * slice_scale;
  } else {
    DCHECK(slice.IsPercent());
    resolved = FloatValueForLength(slice, maximum);
  }
  resolved = std::min(maximum, resolved);
  // Round-trip via LayoutUnit to flush out any "excess" precision.
  return LayoutUnit::FromFloatRound(resolved).ToFloat();
}

// "Round" the edge widths, adhering to the following restrictions:
//
//  1) Perform rounding in the same way as for borders, thus preferring
//     symmetry.
//
//  2) If edges are abutting, then distribute the space (i.e the single pixel)
//     to the edge with the highest coverage - giving the starting edge
//     precedence if tied.
//
gfx::Outsets SnapEdgeWidths(const PhysicalBoxStrut& edge_widths,
                            const gfx::Size& snapped_box_size) {
  gfx::Outsets snapped;
  // Allow a small deviation when checking if the the edges are abutting.
  constexpr LayoutUnit kAbuttingEpsilon(LayoutUnit::Epsilon());
  if (snapped_box_size.width() - edge_widths.HorizontalSum() <=
      kAbuttingEpsilon) {
    snapped.set_left(edge_widths.left.Round());
    snapped.set_right(snapped_box_size.width() - snapped.left());
  } else {
    snapped.set_left(edge_widths.left.Floor());
    snapped.set_right(edge_widths.right.Floor());
  }
  DCHECK_LE(snapped.left() + snapped.right(), snapped_box_size.width());

  if (snapped_box_size.height() - edge_widths.VerticalSum() <=
      kAbuttingEpsilon) {
    snapped.set_top(edge_widths.top.Round());
    snapped.set_bottom(snapped_box_size.height() - snapped.top());
  } else {
    snapped.set_top(edge_widths.top.Floor());
    snapped.set_bottom(edge_widths.bottom.Floor());
  }
  DCHECK_LE(snapped.top() + snapped.bottom(), snapped_box_size.height());
  return snapped;
}

}  // namespace

NinePieceImageGrid::NinePieceImageGrid(const NinePieceImage& nine_piece_image,
                                       const gfx::SizeF& image_size,
                                       const gfx::Vector2dF& slice_scale,
                                       float zoom,
                                       const gfx::Rect& border_image_area,
                                       const gfx::Outsets& border_widths,
                                       PhysicalBoxSides sides_to_include)
    : border_image_area_(border_image_area),
      image_size_(image_size),
      horizontal_tile_rule_(nine_piece_image.HorizontalRule()),
      vertical_tile_rule_(nine_piece_image.VerticalRule()),
      zoom_(zoom),
      fill_(nine_piece_image.Fill()) {
  const LengthBox& image_slices = nine_piece_image.ImageSlices();
  top_.slice = ComputeEdgeSlice(image_slices.Top(), slice_scale.y(),
                                image_size.height());
  right_.slice = ComputeEdgeSlice(image_slices.Right(), slice_scale.x(),
                                  image_size.width());
  bottom_.slice = ComputeEdgeSlice(image_slices.Bottom(), slice_scale.y(),
                                   image_size.height());
  left_.slice = ComputeEdgeSlice(image_slices.Left(), slice_scale.x(),
                                 image_size.width());

  // |Edge::slice| is in image-local units (physical pixels for raster images),
  // but when using it to resolve 'auto' for border-image-widths we want it to
  // be in zoomed CSS pixels, so divide by |slice_scale| and multiply by zoom.
  const gfx::Vector2dF auto_slice_adjustment(zoom / slice_scale.x(),
                                             zoom / slice_scale.y());
  const BorderImageLengthBox& border_slices = nine_piece_image.BorderSlices();
  PhysicalBoxStrut resolved_widths;
  if (sides_to_include.top) {
    resolved_widths.top = ComputeEdgeWidth(
        border_slices.Top(), border_widths.top(),
        top_.slice * auto_slice_adjustment.y(), border_image_area.height());
  }
  if (sides_to_include.right) {
    resolved_widths.right = ComputeEdgeWidth(
        border_slices.Right(), border_widths.right(),
        right_.slice * auto_slice_adjustment.x(), border_image_area.width());
  }
  if (sides_to_include.bottom) {
    resolved_widths.bottom = ComputeEdgeWidth(
        border_slices.Bottom(), border_widths.bottom(),
        bottom_.slice * auto_slice_adjustment.y(), border_image_area.height());
  }
  if (sides_to_include.left) {
    resolved_widths.left = ComputeEdgeWidth(
        border_slices.Left(), border_widths.left(),
        left_.slice * auto_slice_adjustment.x(), border_image_area.width());
  }

  // The spec says: Given Lwidth as the width of the border image area, Lheight
  // as its height, and Wside as the border image width offset for the side, let
  // f = min(Lwidth/(Wleft+Wright), Lheight/(Wtop+Wbottom)). If f < 1, then all
  // W are reduced by multiplying them by f.
  const LayoutUnit border_side_width = resolved_widths.HorizontalSum();
  const LayoutUnit border_side_height = resolved_widths.VerticalSum();
  const float border_side_scale_factor = std::min(
      static_cast<float>(border_image_area.width()) / border_side_width,
      static_cast<float>(border_image_area.height()) / border_side_height);
  if (border_side_scale_factor < 1) {
    resolved_widths.top =
        LayoutUnit(resolved_widths.top * border_side_scale_factor);
    resolved_widths.right =
        LayoutUnit(resolved_widths.right * border_side_scale_factor);
    resolved_widths.bottom =
        LayoutUnit(resolved_widths.bottom * border_side_scale_factor);
    resolved_widths.left =
        LayoutUnit(resolved_widths.left * border_side_scale_factor);
  }

  const gfx::Outsets snapped_widths =
      SnapEdgeWidths(resolved_widths, border_image_area.size());

  top_.width = snapped_widths.top();
  right_.width = snapped_widths.right();
  bottom_.width = snapped_widths.bottom();
  left_.width = snapped_widths.left();
}

// Given a rectangle, construct a subrectangle using offset, width and height.
// Negative offsets are relative to the extent of the given rectangle.
static gfx::RectF Subrect(const gfx::RectF& rect,
                          float offset_x,
                          float offset_y,
                          float width,
                          float height) {
  float base_x = rect.x();
  if (offset_x < 0)
    base_x = rect.right();

  float base_y = rect.y();
  if (offset_y < 0)
    base_y = rect.bottom();

  return gfx::RectF(base_x + offset_x, base_y + offset_y, width, height);
}

static gfx::RectF Subrect(const gfx::Rect& rect,
                          float offset_x,
                          float offset_y,
                          float width,
                          float height) {
  return Subrect(gfx::RectF(rect), offset_x, offset_y, width, height);
}

static gfx::RectF Subrect(const gfx::SizeF& size,
                          float offset_x,
                          float offset_y,
                          float width,
                          float height) {
  return Subrect(gfx::RectF(size), offset_x, offset_y, width, height);
}

static inline void SetCornerPiece(
    NinePieceImageGrid::NinePieceDrawInfo& draw_info,
    bool is_drawable,
    const gfx::RectF& source,
    const gfx::RectF& destination) {
  draw_info.is_drawable = is_drawable;
  if (draw_info.is_drawable) {
    draw_info.source = source;
    draw_info.destination = destination;
  }
}

void NinePieceImageGrid::SetDrawInfoCorner(NinePieceDrawInfo& draw_info,
                                           NinePiece piece) const {
  switch (piece) {
    case kTopLeftPiece:
      SetCornerPiece(
          draw_info, top_.IsDrawable() && left_.IsDrawable(),
          Subrect(image_size_, 0, 0, left_.slice, top_.slice),
          Subrect(border_image_area_, 0, 0, left_.width, top_.width));
      break;
    case kBottomLeftPiece:
      SetCornerPiece(
          draw_info, bottom_.IsDrawable() && left_.IsDrawable(),
          Subrect(image_size_, 0, -bottom_.slice, left_.slice, bottom_.slice),
          Subrect(border_image_area_, 0, -bottom_.width, left_.width,
                  bottom_.width));
      break;
    case kTopRightPiece:
      SetCornerPiece(
          draw_info, top_.IsDrawable() && right_.IsDrawable(),
          Subrect(image_size_, -right_.slice, 0, right_.slice, top_.slice),
          Subrect(border_image_area_, -right_.width, 0, right_.width,
                  top_.width));
      break;
    case kBottomRightPiece:
      SetCornerPiece(draw_info, bottom_.IsDrawable() && right_.IsDrawable(),
                     Subrect(image_size_, -right_.slice, -bottom_.slice,
                             right_.slice, bottom_.slice),
                     Subrect(border_image_area_, -right_.width, -bottom_.width,
                             right_.width, bottom_.width));
      break;
    default:
      NOTREACHED();
  }
}

static inline void SetHorizontalEdge(
    NinePieceImageGrid::NinePieceDrawInfo& draw_info,
    const NinePieceImageGrid::Edge& edge,
    const gfx::RectF& source,
    const gfx::RectF& destination,
    ENinePieceImageRule tile_rule) {
  draw_info.is_drawable =
      edge.IsDrawable() && source.width() > 0 && destination.width() > 0;
  if (draw_info.is_drawable) {
    draw_info.source = source;
    draw_info.destination = destination;
    draw_info.tile_scale = gfx::Vector2dF(edge.Scale(), edge.Scale());
    draw_info.tile_rule = {tile_rule, kStretchImageRule};
  }
}

static inline void SetVerticalEdge(
    NinePieceImageGrid::NinePieceDrawInfo& draw_info,
    const NinePieceImageGrid::Edge& edge,
    const gfx::RectF& source,
    const gfx::RectF& destination,
    ENinePieceImageRule tile_rule) {
  draw_info.is_drawable =
      edge.IsDrawable() && source.height() > 0 && destination.height() > 0;
  if (draw_info.is_drawable) {
    draw_info.source = source;
    draw_info.destination = destination;
    draw_info.tile_scale = gfx::Vector2dF(edge.Scale(), edge.Scale());
    draw_info.tile_rule = {kStretchImageRule, tile_rule};
  }
}

void NinePieceImageGrid::SetDrawInfoEdge(NinePieceDrawInfo& draw_info,
                                         NinePiece piece) const {
  gfx::SizeF edge_source_size =
      image_size_ -
      gfx::SizeF(left_.slice + right_.slice, top_.slice + bottom_.slice);
  gfx::Size edge_destination_size =
      border_image_area_.size() -
      gfx::Size(left_.width + right_.width, top_.width + bottom_.width);

  switch (piece) {
    case kLeftPiece:
      SetVerticalEdge(draw_info, left_,
                      Subrect(image_size_, 0, top_.slice, left_.slice,
                              edge_source_size.height()),
                      Subrect(border_image_area_, 0, top_.width, left_.width,
                              edge_destination_size.height()),
                      vertical_tile_rule_);
      break;
    case kRightPiece:
      SetVerticalEdge(draw_info, right_,
                      Subrect(image_size_, -right_.slice, top_.slice,
                              right_.slice, edge_source_size.height()),
                      Subrect(border_image_area_, -right_.width, top_.width,
                              right_.width, edge_destination_size.height()),
                      vertical_tile_rule_);
      break;
    case kTopPiece:
      SetHorizontalEdge(draw_info, top_,
                        Subrect(image_size_, left_.slice, 0,
                                edge_source_size.width(), top_.slice),
                        Subrect(border_image_area_, left_.width, 0,
                                edge_destination_size.width(), top_.width),
                        horizontal_tile_rule_);
      break;
    case kBottomPiece:
      SetHorizontalEdge(draw_info, bottom_,
                        Subrect(image_size_, left_.slice, -bottom_.slice,
                                edge_source_size.width(), bottom_.slice),
                        Subrect(border_image_area_, left_.width, -bottom_.width,
                                edge_destination_size.width(), bottom_.width),
                        horizontal_tile_rule_);
      break;
    default:
      NOTREACHED();
  }
}

void NinePieceImageGrid::SetDrawInfoMiddle(NinePieceDrawInfo& draw_info) const {
  gfx::SizeF source_size = image_size_ - gfx::SizeF(left_.slice + right_.slice,
                                                    top_.slice + bottom_.slice);
  gfx::Size destination_size =
      border_image_area_.size() -
      gfx::Size(left_.width + right_.width, top_.width + bottom_.width);

  draw_info.is_drawable =
      fill_ && !source_size.IsEmpty() && !destination_size.IsEmpty();
  if (!draw_info.is_drawable)
    return;

  draw_info.source = Subrect(image_size_, left_.slice, top_.slice,
                             source_size.width(), source_size.height());
  draw_info.destination =
      Subrect(border_image_area_, left_.width, top_.width,
              destination_size.width(), destination_size.height());

  gfx::Vector2dF middle_scale_factor(zoom_, zoom_);

  if (top_.IsDrawable())
    middle_scale_factor.set_x(top_.Scale());
  else if (bottom_.IsDrawable())
    middle_scale_factor.set_x(bottom_.Scale());

  if (left_.IsDrawable())
    middle_scale_factor.set_y(left_.Scale());
  else if (right_.IsDrawable())
    middle_scale_factor.set_y(right_.Scale());

  if (!source_size.IsEmpty()) {
    // For "stretch" rules, just override the scale factor and replace. We only
    // have to do this for the center tile, since sides don't even use the scale
    // factor unless they have a rule other than "stretch". The middle however
    // can have "stretch" specified in one axis but not the other, so we have to
    // correct the scale here.
    if (horizontal_tile_rule_ == kStretchImageRule) {
      middle_scale_factor.set_x(destination_size.width() / source_size.width());
    }
    if (vertical_tile_rule_ == kStretchImageRule) {
      middle_scale_factor.set_y(destination_size.height() /
                                source_size.height());
    }
  }

  draw_info.tile_scale = middle_scale_factor;
  draw_info.tile_rule = {horizontal_tile_rule_, vertical_tile_rule_};
}

NinePieceImageGrid::NinePieceDrawInfo NinePieceImageGrid::GetNinePieceDrawInfo(
    NinePiece piece) const {
  NinePieceDrawInfo draw_info;
  draw_info.is_corner_piece =
      piece == kTopLeftPiece || piece == kTopRightPiece ||
      piece == kBottomLeftPiece || piece == kBottomRightPiece;

  if (draw_info.is_corner_piece)
    SetDrawInfoCorner(draw_info, piece);
  else if (piece != kMiddlePiece)
    SetDrawInfoEdge(draw_info, piece);
  else
    SetDrawInfoMiddle(draw_info);

  return draw_info;
}

}  // namespace blink

"""

```