Response:
The user wants a summary of the functionality of the provided C++ code snippet from Chromium's Blink rendering engine. I need to identify the core purpose of this `box_border_painter.cc` file and how it relates to web technologies (HTML, CSS, JavaScript). I should also consider the implications of the code in terms of common user errors and debugging.

Here's a breakdown of the code's functionality:

1. **Border Drawing:** The code clearly deals with drawing borders around boxes. This is the primary function.
2. **Border Styles:** It handles different CSS border styles like `solid`, `dashed`, `dotted`, `double`, `groove`, `ridge`, `inset`, and `outset`.
3. **Rounded Borders:**  The presence of `FloatRoundedRect` and related calculations suggests it handles rounded corners.
4. **Color Handling:**  It manages border colors, potentially including adjustments for `inset` and `outset` styles to create 3D effects.
5. **Optimization:**  The grouping of edges by opacity suggests an optimization strategy to reduce unnecessary drawing operations.
6. **Anti-aliasing:**  The code explicitly manages anti-aliasing for smoother border rendering.
7. **Dark Mode:** The inclusion of `AutoDarkMode` indicates support for adapting border colors in dark mode.
8. **Overdraw Prevention:** The logic involving `completed_edges` and `WillOverdraw` hints at an attempt to avoid redundant drawing.
9. **Bleed Avoidance:** The `BackgroundBleedAvoidance` enum and related logic suggest mechanisms to prevent background colors from bleeding under rounded borders.

**Relationship to Web Technologies:**

* **CSS:** This code directly implements the visual rendering of CSS border properties.
* **HTML:** The borders being painted are associated with HTML elements.
* **JavaScript:** While this specific code is C++, JavaScript can manipulate the CSS properties that this code renders.

**Hypothetical Input/Output (Conceptual):**

* **Input:**  CSS style for an HTML element: `border: 2px solid red; border-radius: 5px;`
* **Output:**  Drawing commands for the graphics context to render a 2-pixel solid red border with 5-pixel rounded corners.

**Common User/Programming Errors:**

* **Conflicting Border Styles:**  Specifying different styles for individual border sides that might lead to unexpected rendering at the corners.
* **Incorrect Border Widths:**  Setting border widths to zero or negative values, although the code might handle zero, negative values are usually invalid.
* **Opacity Issues:**  Overlapping elements with different opacity values can lead to visual artifacts if not handled correctly.

**User Operation to Reach This Code:**

A user viewing a webpage triggers the rendering process. Here's a simplified flow:

1. **HTML Parsing:** The browser parses the HTML structure.
2. **CSS Parsing & Styling:** The browser parses the CSS and computes the final styles for each HTML element.
3. **Layout:** The browser calculates the position and size of elements on the page.
4. **Painting:** The browser iterates through the elements and their styles, calling the appropriate painting routines. For elements with borders, `BoxBorderPainter::Paint()` would be invoked, leading to the execution of the code in this file.

**Summary of Functionality (Part 1):**

This code snippet from `box_border_painter.cc` is responsible for **managing and organizing the drawing of borders around rectangular boxes in the Blink rendering engine**. It sets up the data structures and logic for handling different border properties like style, color, width, and opacity, and it starts the process of sorting and grouping border edges for efficient rendering. The code initializes the collection of visible border edges based on the provided `border_painter`.

这是 `blink/renderer/core/paint/box_border_painter.cc` 文件的一部分，其主要功能是 **负责绘制 HTML 元素的边框 (border)**。

以下是它的具体功能归纳：

1. **管理边框绘制的信息:**  代码中定义了 `ComplexBorderInfo` 结构体，用于存储和组织需要绘制的边框信息，包括按不透明度分组的边和它们的绘制顺序。
2. **确定可见边:** 代码开始遍历元素的四个边 (上、右、下、左)，并判断哪些边是可见的（例如，`border-style` 不是 `none` 或 `hidden`，且 `border-width` 大于 0）。
3. **按不透明度分组:**  将具有相同不透明度的边分到同一个 `OpacityGroup` 中。这是一种优化策略，可以减少图形上下文切换的次数。
4. **确定绘制顺序:**  对于每个不透明度组内的边，代码会根据边框的样式 (例如，虚线、实线) 和边的位置 (相邻或不相邻) 确定一个绘制优先级。这是为了优化绘制效果，例如，先绘制非实线边，以便实线边可以覆盖它们，从而避免潜在的渲染问题。

**它与 javascript, html, css 的功能关系：**

* **CSS:**  这个 C++ 代码直接实现了 CSS 边框属性的渲染。当 CSS 中定义了 `border-style`, `border-color`, `border-width`, `border-radius`, `opacity` 等属性时，这个代码会被调用来将这些样式渲染到屏幕上。
    * **举例:**
        * **HTML:** `<div style="border: 2px solid red;"></div>`
        * **CSS:**  这段 CSS 声明会触发 `box_border_painter.cc` 中的代码，绘制一个 2 像素宽的红色实线边框。
        * **CSS:**  `opacity: 0.5;` 这个 CSS 属性会影响边框的不透明度，代码会将这个边与其他具有相同不透明度的边分组在一起绘制。
* **HTML:**  HTML 元素是边框的载体。这段代码负责绘制应用于 HTML 元素的边框。
* **JavaScript:** JavaScript 可以动态地修改 HTML 元素的 CSS 样式，包括边框属性。当 JavaScript 修改了边框相关的 CSS 属性后，浏览器的渲染引擎会重新调用 `box_border_painter.cc` 中的代码来更新边框的绘制。
    * **举例:**
        * **JavaScript:** `document.querySelector('div').style.borderColor = 'blue';`
        *  这段 JavaScript 代码会修改 div 元素的边框颜色，导致 `box_border_painter.cc` 中的代码被调用，并使用新的蓝色来重新绘制边框。

**逻辑推理（假设输入与输出）：**

假设我们有一个 HTML 元素，其 CSS 样式如下：

```css
.my-box {
  border-top: 1px dashed black;
  border-right: 2px solid blue;
  border-bottom: 1px dotted black;
  border-left: 2px solid green;
  opacity: 0.8;
}
```

**假设输入:**  `border_painter` 对象包含了上述 CSS 样式信息。

**逻辑推理过程:**

1. 代码会遍历四个边。
2. 上边 (`dashed`) 和下边 (`dotted`) 的 `border-style` 不是实线，优先级可能较高。
3. 右边 (`solid`) 和左边 (`solid`) 的 `border-style` 是实线，优先级可能较低。
4. 所有边的 `opacity` 都是 0.8，因此它们会被分到同一个 `OpacityGroup` 中。
5. 在同一个不透明度组内，会根据边框样式和位置进一步排序。例如，非相邻的边可能优先绘制，以减少需要进行斜接处理的角。

**可能的输出 (排序后的边):** 上边 (dashed), 下边 (dotted), 右边 (solid), 左边 (solid)  (具体顺序可能更复杂，取决于更细致的优先级规则)。

**用户或编程常见的使用错误：**

1. **忘记设置边框样式:**  如果只设置了 `border-width` 和 `border-color`，而没有设置 `border-style`，边框将不会显示 (默认为 `none`)。
    * **举例:** `<div style="border-width: 2px; border-color: red;"></div>`  这段代码不会显示边框。
2. **边框宽度设置为 0:** 如果 `border-width` 设置为 0，边框也不会显示，即使设置了 `border-style` 和 `border-color`。
    * **举例:** `<div style="border: 0 solid red;"></div>` 这段代码不会显示边框。
3. **不正确的颜色值:**  使用了无效的颜色值可能导致边框显示为默认颜色或不显示。
4. **层叠上下文问题:**  如果元素被其他具有层叠上下文的元素遮挡，即使边框被正确绘制，也可能看不到。
5. **在变换或动画过程中出现渲染问题:** 复杂的 CSS 变换或动画可能导致边框渲染出现意想不到的效果，例如锯齿或闪烁。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器中打开一个网页。**
2. **浏览器开始解析 HTML 代码，构建 DOM 树。**
3. **浏览器解析 CSS 样式，包括外部样式表和内联样式。**
4. **浏览器计算每个元素的最终样式 (Computed Style)，包括边框属性。**
5. **当浏览器需要绘制某个具有边框的元素时，渲染引擎会调用 `Paint()` 函数或类似的方法。**
6. **在 `Paint()` 过程中，如果元素有边框，会创建或获取一个 `BoxBorderPainter` 对象。**
7. **`BoxBorderPainter::Paint()` 方法会被调用，该方法会调用本文件中定义的相关函数来绘制边框。**
8. **调试线索:**  如果在网页上元素的边框显示不正确，开发者可以使用浏览器的开发者工具 (例如 Chrome DevTools) 来检查元素的 CSS 样式，确认边框属性是否设置正确。他们还可以使用断点调试等工具，追踪渲染引擎的执行流程，查看 `BoxBorderPainter` 对象的属性和调用堆栈，从而定位问题。

**总结 (第 1 部分的功能):**

总而言之，这段代码的功能是 **初始化并组织 HTML 元素边框的绘制过程**。它识别可见的边，并根据它们的不透明度、样式和位置进行分组和排序，为后续的实际绘制操作做准备。这部分代码主要关注的是 **数据的组织和预处理**，为高效且正确的边框渲染奠定基础。

Prompt: 
```
这是目录为blink/renderer/core/paint/box_border_painter.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/box_border_painter.h"

#include <algorithm>

#include "third_party/blink/renderer/core/paint/box_painter.h"
#include "third_party/blink/renderer/core/paint/object_painter.h"
#include "third_party/blink/renderer/core/paint/paint_auto_dark_mode.h"
#include "third_party/blink/renderer/core/paint/rounded_border_geometry.h"
#include "third_party/blink/renderer/core/style/border_edge.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context_state_saver.h"
#include "third_party/blink/renderer/platform/graphics/skia/skia_utils.h"
#include "third_party/blink/renderer/platform/graphics/stroke_data.h"
#include "third_party/blink/renderer/platform/graphics/styled_stroke_data.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "ui/gfx/color_utils.h"
#include "ui/gfx/geometry/rect_conversions.h"

namespace blink {

namespace {

enum BorderEdgeFlag {
  kTopBorderEdge = 1 << static_cast<unsigned>(BoxSide::kTop),
  kRightBorderEdge = 1 << static_cast<unsigned>(BoxSide::kRight),
  kBottomBorderEdge = 1 << static_cast<unsigned>(BoxSide::kBottom),
  kLeftBorderEdge = 1 << static_cast<unsigned>(BoxSide::kLeft),
  kAllBorderEdges =
      kTopBorderEdge | kBottomBorderEdge | kLeftBorderEdge | kRightBorderEdge
};

inline BorderEdgeFlag EdgeFlagForSide(BoxSide side) {
  return static_cast<BorderEdgeFlag>(1 << static_cast<unsigned>(side));
}

inline bool IncludesEdge(BorderEdgeFlags flags, BoxSide side) {
  return flags & EdgeFlagForSide(side);
}

inline bool IncludesAdjacentEdges(BorderEdgeFlags flags) {
  // The set includes adjacent edges iff it contains at least one horizontal and
  // one vertical edge.
  return (flags & (kTopBorderEdge | kBottomBorderEdge)) &&
         (flags & (kLeftBorderEdge | kRightBorderEdge));
}

inline bool StyleRequiresClipPolygon(EBorderStyle style) {
  // These are drawn with a stroke, so we have to clip to get corner miters.
  return style == EBorderStyle::kDotted || style == EBorderStyle::kDashed;
}

inline bool BorderStyleFillsBorderArea(EBorderStyle style) {
  return !(style == EBorderStyle::kDotted || style == EBorderStyle::kDashed ||
           style == EBorderStyle::kDouble);
}

inline bool BorderStyleHasInnerDetail(EBorderStyle style) {
  return style == EBorderStyle::kGroove || style == EBorderStyle::kRidge ||
         style == EBorderStyle::kDouble;
}

inline bool BorderStyleIsDottedOrDashed(EBorderStyle style) {
  return style == EBorderStyle::kDotted || style == EBorderStyle::kDashed;
}

// BorderStyleOutset darkens the bottom and right (and maybe lightens the top
// and left) BorderStyleInset darkens the top and left (and maybe lightens the
// bottom and right).
inline bool BorderStyleHasUnmatchedColorsAtCorner(EBorderStyle style,
                                                  BoxSide side,
                                                  BoxSide adjacent_side) {
  // These styles match at the top/left and bottom/right.
  if (style == EBorderStyle::kInset || style == EBorderStyle::kGroove ||
      style == EBorderStyle::kRidge || style == EBorderStyle::kOutset) {
    const BorderEdgeFlags top_right_flags =
        EdgeFlagForSide(BoxSide::kTop) | EdgeFlagForSide(BoxSide::kRight);
    const BorderEdgeFlags bottom_left_flags =
        EdgeFlagForSide(BoxSide::kBottom) | EdgeFlagForSide(BoxSide::kLeft);

    BorderEdgeFlags flags =
        EdgeFlagForSide(side) | EdgeFlagForSide(adjacent_side);
    return flags == top_right_flags || flags == bottom_left_flags;
  }
  return false;
}

inline bool BorderWillArcInnerEdge(const gfx::SizeF& first_radius,
                                   const gfx::SizeF& second_radius) {
  return !first_radius.IsZero() || !second_radius.IsZero();
}

inline bool WillOverdraw(BoxSide side,
                         EBorderStyle style,
                         BorderEdgeFlags completed_edges) {
  // If we're done with this side, it will obviously not overdraw any portion of
  // the current edge.
  if (IncludesEdge(completed_edges, side))
    return false;

  // The side is still to be drawn. It overdraws the current edge iff it has a
  // solid fill style.
  return BorderStyleFillsBorderArea(style);
}

inline bool BorderStylesRequireMiter(BoxSide side,
                                     BoxSide adjacent_side,
                                     EBorderStyle style,
                                     EBorderStyle adjacent_style) {
  if (style == EBorderStyle::kDouble ||
      adjacent_style == EBorderStyle::kDouble ||
      adjacent_style == EBorderStyle::kGroove ||
      adjacent_style == EBorderStyle::kRidge)
    return true;

  if (BorderStyleIsDottedOrDashed(style) !=
      BorderStyleIsDottedOrDashed(adjacent_style))
    return true;

  if (style != adjacent_style)
    return true;

  return BorderStyleHasUnmatchedColorsAtCorner(style, side, adjacent_side);
}

void SetToRightSideRect(gfx::Rect& rect, int edge_width) {
  rect.set_x(rect.right() - edge_width);
  rect.set_width(edge_width);
}

void SetToBottomSideRect(gfx::Rect& rect, int edge_width) {
  rect.set_y(rect.bottom() - edge_width);
  rect.set_height(edge_width);
}

gfx::Rect CalculateSideRect(const FloatRoundedRect& outer_border,
                            const BorderEdge& edge,
                            BoxSide side) {
  gfx::Rect side_rect = gfx::ToRoundedRect(outer_border.Rect());
  int width = edge.Width();

  switch (side) {
    case BoxSide::kTop:
      side_rect.set_height(width);
      break;
    case BoxSide::kBottom:
      SetToBottomSideRect(side_rect, width);
      break;
    case BoxSide::kLeft:
      side_rect.set_width(width);
      break;
    case BoxSide::kRight:
      SetToRightSideRect(side_rect, width);
      break;
  }
  return side_rect;
}

FloatRoundedRect CalculateAdjustedInnerBorder(
    const FloatRoundedRect& inner_border,
    BoxSide side) {
  // Expand the inner border as necessary to make it a rounded rect (i.e. radii
  // contained within each edge).  This function relies on the fact we only get
  // radii not contained within each edge if one of the radii for an edge is
  // zero, so we can shift the arc towards the zero radius corner.
  FloatRoundedRect::Radii new_radii = inner_border.GetRadii();
  gfx::RectF new_rect = inner_border.Rect();

  float overshoot;
  float max_radii;

  switch (side) {
    case BoxSide::kTop:
      overshoot = new_radii.TopLeft().width() + new_radii.TopRight().width() -
                  new_rect.width();
      // FIXME: once we start pixel-snapping rounded rects after this point, the
      // overshoot concept should disappear.
      if (overshoot > 0.1) {
        new_rect.set_width(new_rect.width() + overshoot);
        if (!new_radii.TopLeft().width())
          new_rect.Offset(-overshoot, 0);
      }
      new_radii.SetBottomLeft(gfx::SizeF(0, 0));
      new_radii.SetBottomRight(gfx::SizeF(0, 0));
      max_radii =
          std::max(new_radii.TopLeft().height(), new_radii.TopRight().height());
      if (max_radii > new_rect.height())
        new_rect.set_height(max_radii);
      break;

    case BoxSide::kBottom:
      overshoot = new_radii.BottomLeft().width() +
                  new_radii.BottomRight().width() - new_rect.width();
      if (overshoot > 0.1) {
        new_rect.set_width(new_rect.width() + overshoot);
        if (!new_radii.BottomLeft().width())
          new_rect.Offset(-overshoot, 0);
      }
      new_radii.SetTopLeft(gfx::SizeF(0, 0));
      new_radii.SetTopRight(gfx::SizeF(0, 0));
      max_radii = std::max(new_radii.BottomLeft().height(),
                           new_radii.BottomRight().height());
      if (max_radii > new_rect.height()) {
        new_rect.Offset(0, new_rect.height() - max_radii);
        new_rect.set_height(max_radii);
      }
      break;

    case BoxSide::kLeft:
      overshoot = new_radii.TopLeft().height() +
                  new_radii.BottomLeft().height() - new_rect.height();
      if (overshoot > 0.1) {
        new_rect.set_height(new_rect.height() + overshoot);
        if (!new_radii.TopLeft().height())
          new_rect.Offset(0, -overshoot);
      }
      new_radii.SetTopRight(gfx::SizeF(0, 0));
      new_radii.SetBottomRight(gfx::SizeF(0, 0));
      max_radii =
          std::max(new_radii.TopLeft().width(), new_radii.BottomLeft().width());
      if (max_radii > new_rect.width())
        new_rect.set_width(max_radii);
      break;

    case BoxSide::kRight:
      overshoot = new_radii.TopRight().height() +
                  new_radii.BottomRight().height() - new_rect.height();
      if (overshoot > 0.1) {
        new_rect.set_height(new_rect.height() + overshoot);
        if (!new_radii.TopRight().height())
          new_rect.Offset(0, -overshoot);
      }
      new_radii.SetTopLeft(gfx::SizeF(0, 0));
      new_radii.SetBottomLeft(gfx::SizeF(0, 0));
      max_radii = std::max(new_radii.TopRight().width(),
                           new_radii.BottomRight().width());
      if (max_radii > new_rect.width()) {
        new_rect.Offset(new_rect.width() - max_radii, 0);
        new_rect.set_width(max_radii);
      }
      break;
  }

  return FloatRoundedRect(new_rect, new_radii);
}

void DrawSolidBorderRect(GraphicsContext& context,
                         const gfx::Rect& border_rect,
                         int border_width,
                         const Color& color,
                         const AutoDarkMode& auto_dark_mode) {
  gfx::RectF stroke_rect(border_rect);
  stroke_rect.Outset(-border_width / 2.f);

  bool was_antialias = context.ShouldAntialias();
  if (!was_antialias)
    context.SetShouldAntialias(true);

  context.SetStrokeColor(color);
  context.SetStrokeThickness(border_width);
  context.StrokeRect(stroke_rect, auto_dark_mode);

  if (!was_antialias)
    context.SetShouldAntialias(false);
}

void DrawBleedAdjustedDRRect(GraphicsContext& context,
                             BackgroundBleedAvoidance bleed_avoidance,
                             const FloatRoundedRect& outer,
                             const FloatRoundedRect& inner,
                             Color color,
                             const AutoDarkMode& auto_dark_mode) {
  switch (bleed_avoidance) {
    case kBackgroundBleedClipLayer: {
      // BackgroundBleedClipLayer clips the outer rrect for the whole layer.
      // Based on this, we can avoid background bleeding by filling the
      // *outside* of inner rrect, all the way to the layer bounds (enclosing
      // int rect for the clip, in device space).
      SkPath path;
      path.addRRect(SkRRect(inner));
      path.setFillType(SkPathFillType::kInverseWinding);

      cc::PaintFlags flags;
      flags.setColor(color.toSkColor4f());
      flags.setStyle(cc::PaintFlags::kFill_Style);
      flags.setAntiAlias(true);
      context.DrawPath(path, flags, auto_dark_mode);

      break;
    }
    case kBackgroundBleedClipOnly:
      if (outer.IsRounded()) {
        // BackgroundBleedClipOnly clips the outer rrect corners for us.
        FloatRoundedRect adjusted_outer = outer;
        adjusted_outer.SetRadii(FloatRoundedRect::Radii());
        context.FillDRRect(adjusted_outer, inner, color, auto_dark_mode);
        break;
      }
      [[fallthrough]];
    default:
      context.FillDRRect(outer, inner, color, auto_dark_mode);
      break;
  }
}

// The LUTs below assume specific enum values.
static_assert(EBorderStyle::kNone == static_cast<EBorderStyle>(0),
              "unexpected EBorderStyle value");
static_assert(EBorderStyle::kHidden == static_cast<EBorderStyle>(1),
              "unexpected EBorderStyle value");
static_assert(EBorderStyle::kInset == static_cast<EBorderStyle>(2),
              "unexpected EBorderStyle value");
static_assert(EBorderStyle::kGroove == static_cast<EBorderStyle>(3),
              "unexpected EBorderStyle value");
static_assert(EBorderStyle::kOutset == static_cast<EBorderStyle>(4),
              "unexpected EBorderStyle value");
static_assert(EBorderStyle::kRidge == static_cast<EBorderStyle>(5),
              "unexpected EBorderStyle value");
static_assert(EBorderStyle::kDotted == static_cast<EBorderStyle>(6),
              "unexpected EBorderStyle value");
static_assert(EBorderStyle::kDashed == static_cast<EBorderStyle>(7),
              "unexpected EBorderStyle value");
static_assert(EBorderStyle::kSolid == static_cast<EBorderStyle>(8),
              "unexpected EBorderStyle value");
static_assert(EBorderStyle::kDouble == static_cast<EBorderStyle>(9),
              "unexpected EBorderStyle value");

static_assert(static_cast<unsigned>(BoxSide::kTop) == 0,
              "unexpected BoxSide value");
static_assert(static_cast<unsigned>(BoxSide::kRight) == 1,
              "unexpected BoxSide value");
static_assert(static_cast<unsigned>(BoxSide::kBottom) == 2,
              "unexpected BoxSide value");
static_assert(static_cast<unsigned>(BoxSide::kLeft) == 3,
              "unexpected BoxSide value");

// Style-based paint order: non-solid edges (dashed/dotted/double) are painted
// before solid edges (inset/outset/groove/ridge/solid) to maximize overdraw
// opportunities.
const auto kStylePriority = std::to_array<unsigned>({
    0,  // EBorderStyle::kNone
    0,  // EBorderStyle::kHidden
    2,  // EBorderStyle::kInset
    2,  // EBorderStyle::kGroove
    2,  // EBorderStyle::kOutset
    2,  // EBorderStyle::kRidge,
    1,  // EBorderStyle::kDotted
    1,  // EBorderStyle::kDashed
    3,  // EBorderStyle::kSolid
    1,  // EBorderStyle::kDouble
});

// Given the same style, prefer drawing in non-adjacent order to minimize the
// number of sides which require miters.
const auto kSidePriority = std::to_array<unsigned>({
    0,  // BoxSide::kTop
    2,  // BoxSide::kRight
    1,  // BoxSide::kBottom
    3,  // BoxSide::kLeft
});

// Edges sharing the same opacity. Stores both a side list and an edge bitfield
// to support constant time iteration + membership tests.
struct OpacityGroup {
  DISALLOW_NEW();

 public:
  explicit OpacityGroup(float alpha) : edge_flags(0), alpha(alpha) {}

  Vector<BoxSide, 4> sides;
  BorderEdgeFlags edge_flags;
  float alpha;
};

void ClipPolygon(GraphicsContext& context,
                 base::span<const gfx::PointF> vertices,
                 bool antialiased) {
  SkPath path;
  path.moveTo(gfx::PointFToSkPoint(vertices[0]));
  for (size_t i = 1; i < vertices.size(); ++i) {
    path.lineTo(gfx::PointFToSkPoint(vertices[i]));
  }

  context.ClipPath(path, antialiased ? kAntiAliased : kNotAntiAliased);
}

void DrawDashedOrDottedBoxSide(GraphicsContext& context,
                               int x1,
                               int y1,
                               int x2,
                               int y2,
                               BoxSide side,
                               Color color,
                               int thickness,
                               EBorderStyle style,
                               bool antialias,
                               const AutoDarkMode& auto_dark_mode) {
  DCHECK_GT(thickness, 0);

  GraphicsContextStateSaver state_saver(context);
  context.SetShouldAntialias(antialias);
  context.SetStrokeColor(color);
  StyledStrokeData styled_stroke;
  styled_stroke.SetThickness(thickness);
  styled_stroke.SetStyle(style == EBorderStyle::kDashed ? kDashedStroke
                                                        : kDottedStroke);

  switch (side) {
    case BoxSide::kBottom:
    case BoxSide::kTop: {
      int mid_y = y1 + thickness / 2;
      context.DrawLine(gfx::Point(x1, mid_y), gfx::Point(x2, mid_y),
                       styled_stroke, auto_dark_mode);
      break;
    }
    case BoxSide::kRight:
    case BoxSide::kLeft: {
      int mid_x = x1 + thickness / 2;
      context.DrawLine(gfx::Point(mid_x, y1), gfx::Point(mid_x, y2),
                       styled_stroke, auto_dark_mode);
      break;
    }
  }
}

void DrawLineForBoxSide(GraphicsContext& context,
                        int x1,
                        int y1,
                        int x2,
                        int y2,
                        BoxSide side,
                        Color color,
                        EBorderStyle style,
                        int adjacent_width1,
                        int adjacent_width2,
                        bool antialias,
                        const AutoDarkMode& auto_dark_mode);

Color CalculateBorderStyleColor(const EBorderStyle& style,
                                const BoxSide& side,
                                const Color& color) {
  bool is_darken = (side == BoxSide::kTop || side == BoxSide::kLeft) ==
                   (style == EBorderStyle::kInset);

  Color dark_color = color.Dark();
  // Inset, outset, ridge, and groove paint a darkened or "shadow" edge:
  // https://w3c.github.io/csswg-drafts/css-backgrounds/#border-style. By
  // default, darken |color| for the darker edge and use |color| for the lighter
  // edge.
  if (is_darken) {
    return dark_color;
  }

  auto should_lighten_color = [color, dark_color]() -> bool {
    // This constant is used to determine if there is enough contrast between
    // the darkened edge and |color|. If not, also lighten |color| for the
    // lighter edge.
    constexpr float kMinimumBorderEdgeContrastRatio = 1.75f;
    return color_utils::GetContrastRatio(color.toSkColor4f(),
                                         dark_color.toSkColor4f()) <
           kMinimumBorderEdgeContrastRatio;
  };
  // The following condition skips should_lighten_color() when the result is
  // know to be false. The values came from a brute force search of r, b, g
  // values, see https://crrev.com/c/4200827/3.
  if (color.Red() >= 150 || color.Green() >= 92) {
    DCHECK(!should_lighten_color());
    return color;
  }
  return should_lighten_color() ? color.Light() : color;
}

void DrawDoubleBoxSide(GraphicsContext& context,
                       int x1,
                       int y1,
                       int x2,
                       int y2,
                       int length,
                       BoxSide side,
                       Color color,
                       int thickness,
                       int adjacent_width1,
                       int adjacent_width2,
                       bool antialias,
                       const AutoDarkMode& auto_dark_mode) {
  int third_of_thickness = (thickness + 1) / 3;
  DCHECK_GT(third_of_thickness, 0);

  if (!adjacent_width1 && !adjacent_width2) {
    context.SetFillColor(color);

    bool was_antialiased = context.ShouldAntialias();
    context.SetShouldAntialias(antialias);

    switch (side) {
      case BoxSide::kTop:
      case BoxSide::kBottom:
        context.FillRect(gfx::Rect(x1, y1, length, third_of_thickness),
                         auto_dark_mode);
        context.FillRect(
            gfx::Rect(x1, y2 - third_of_thickness, length, third_of_thickness),
            auto_dark_mode);
        break;
      case BoxSide::kLeft:
      case BoxSide::kRight:
        context.FillRect(gfx::Rect(x1, y1, third_of_thickness, length),
                         auto_dark_mode);
        context.FillRect(
            gfx::Rect(x2 - third_of_thickness, y1, third_of_thickness, length),
            auto_dark_mode);
        break;
    }

    context.SetShouldAntialias(was_antialiased);
    return;
  }

  int adjacent1_big_third =
      ((adjacent_width1 > 0) ? adjacent_width1 + 1 : adjacent_width1 - 1) / 3;
  int adjacent2_big_third =
      ((adjacent_width2 > 0) ? adjacent_width2 + 1 : adjacent_width2 - 1) / 3;

  switch (side) {
    case BoxSide::kTop:
      DrawLineForBoxSide(
          context, x1 + std::max((-adjacent_width1 * 2 + 1) / 3, 0), y1,
          x2 - std::max((-adjacent_width2 * 2 + 1) / 3, 0),
          y1 + third_of_thickness, side, color, EBorderStyle::kSolid,
          adjacent1_big_third, adjacent2_big_third, antialias, auto_dark_mode);
      DrawLineForBoxSide(context,
                         x1 + std::max((adjacent_width1 * 2 + 1) / 3, 0),
                         y2 - third_of_thickness,
                         x2 - std::max((adjacent_width2 * 2 + 1) / 3, 0), y2,
                         side, color, EBorderStyle::kSolid, adjacent1_big_third,
                         adjacent2_big_third, antialias, auto_dark_mode);
      break;
    case BoxSide::kLeft:
      DrawLineForBoxSide(context, x1,
                         y1 + std::max((-adjacent_width1 * 2 + 1) / 3, 0),
                         x1 + third_of_thickness,
                         y2 - std::max((-adjacent_width2 * 2 + 1) / 3, 0), side,
                         color, EBorderStyle::kSolid, adjacent1_big_third,
                         adjacent2_big_third, antialias, auto_dark_mode);
      DrawLineForBoxSide(context, x2 - third_of_thickness,
                         y1 + std::max((adjacent_width1 * 2 + 1) / 3, 0), x2,
                         y2 - std::max((adjacent_width2 * 2 + 1) / 3, 0), side,
                         color, EBorderStyle::kSolid, adjacent1_big_third,
                         adjacent2_big_third, antialias, auto_dark_mode);
      break;
    case BoxSide::kBottom:
      DrawLineForBoxSide(
          context, x1 + std::max((adjacent_width1 * 2 + 1) / 3, 0), y1,
          x2 - std::max((adjacent_width2 * 2 + 1) / 3, 0),
          y1 + third_of_thickness, side, color, EBorderStyle::kSolid,
          adjacent1_big_third, adjacent2_big_third, antialias, auto_dark_mode);
      DrawLineForBoxSide(context,
                         x1 + std::max((-adjacent_width1 * 2 + 1) / 3, 0),
                         y2 - third_of_thickness,
                         x2 - std::max((-adjacent_width2 * 2 + 1) / 3, 0), y2,
                         side, color, EBorderStyle::kSolid, adjacent1_big_third,
                         adjacent2_big_third, antialias, auto_dark_mode);
      break;
    case BoxSide::kRight:
      DrawLineForBoxSide(context, x1,
                         y1 + std::max((adjacent_width1 * 2 + 1) / 3, 0),
                         x1 + third_of_thickness,
                         y2 - std::max((adjacent_width2 * 2 + 1) / 3, 0), side,
                         color, EBorderStyle::kSolid, adjacent1_big_third,
                         adjacent2_big_third, antialias, auto_dark_mode);
      DrawLineForBoxSide(context, x2 - third_of_thickness,
                         y1 + std::max((-adjacent_width1 * 2 + 1) / 3, 0), x2,
                         y2 - std::max((-adjacent_width2 * 2 + 1) / 3, 0), side,
                         color, EBorderStyle::kSolid, adjacent1_big_third,
                         adjacent2_big_third, antialias, auto_dark_mode);
      break;
    default:
      break;
  }
}

void DrawRidgeOrGrooveBoxSide(GraphicsContext& context,
                              int x1,
                              int y1,
                              int x2,
                              int y2,
                              BoxSide side,
                              Color color,
                              EBorderStyle style,
                              int adjacent_width1,
                              int adjacent_width2,
                              bool antialias,
                              const AutoDarkMode& auto_dark_mode) {
  EBorderStyle s1;
  EBorderStyle s2;
  if (style == EBorderStyle::kGroove) {
    s1 = EBorderStyle::kInset;
    s2 = EBorderStyle::kOutset;
  } else {
    s1 = EBorderStyle::kOutset;
    s2 = EBorderStyle::kInset;
  }

  int adjacent1_big_half =
      ((adjacent_width1 > 0) ? adjacent_width1 + 1 : adjacent_width1 - 1) / 2;
  int adjacent2_big_half =
      ((adjacent_width2 > 0) ? adjacent_width2 + 1 : adjacent_width2 - 1) / 2;

  switch (side) {
    case BoxSide::kTop:
      DrawLineForBoxSide(context, x1 + std::max(-adjacent_width1, 0) / 2, y1,
                         x2 - std::max(-adjacent_width2, 0) / 2,
                         (y1 + y2 + 1) / 2, side, color, s1, adjacent1_big_half,
                         adjacent2_big_half, antialias, auto_dark_mode);
      DrawLineForBoxSide(
          context, x1 + std::max(adjacent_width1 + 1, 0) / 2, (y1 + y2 + 1) / 2,
          x2 - std::max(adjacent_width2 + 1, 0) / 2, y2, side, color, s2,
          adjacent_width1 / 2, adjacent_width2 / 2, antialias, auto_dark_mode);
      break;
    case BoxSide::kLeft:
      DrawLineForBoxSide(context, x1, y1 + std::max(-adjacent_width1, 0) / 2,
                         (x1 + x2 + 1) / 2,
                         y2 - std::max(-adjacent_width2, 0) / 2, side, color,
                         s1, adjacent1_big_half, adjacent2_big_half, antialias,
                         auto_dark_mode);
      DrawLineForBoxSide(
          context, (x1 + x2 + 1) / 2, y1 + std::max(adjacent_width1 + 1, 0) / 2,
          x2, y2 - std::max(adjacent_width2 + 1, 0) / 2, side, color, s2,
          adjacent_width1 / 2, adjacent_width2 / 2, antialias, auto_dark_mode);
      break;
    case BoxSide::kBottom:
      DrawLineForBoxSide(context, x1 + std::max(adjacent_width1, 0) / 2, y1,
                         x2 - std::max(adjacent_width2, 0) / 2,
                         (y1 + y2 + 1) / 2, side, color, s2, adjacent1_big_half,
                         adjacent2_big_half, antialias, auto_dark_mode);
      DrawLineForBoxSide(context, x1 + std::max(-adjacent_width1 + 1, 0) / 2,
                         (y1 + y2 + 1) / 2,
                         x2 - std::max(-adjacent_width2 + 1, 0) / 2, y2, side,
                         color, s1, adjacent_width1 / 2, adjacent_width2 / 2,
                         antialias, auto_dark_mode);
      break;
    case BoxSide::kRight:
      DrawLineForBoxSide(
          context, x1, y1 + std::max(adjacent_width1, 0) / 2, (x1 + x2 + 1) / 2,
          y2 - std::max(adjacent_width2, 0) / 2, side, color, s2,
          adjacent1_big_half, adjacent2_big_half, antialias, auto_dark_mode);
      DrawLineForBoxSide(context, (x1 + x2 + 1) / 2,
                         y1 + std::max(-adjacent_width1 + 1, 0) / 2, x2,
                         y2 - std::max(-adjacent_width2 + 1, 0) / 2, side,
                         color, s1, adjacent_width1 / 2, adjacent_width2 / 2,
                         antialias, auto_dark_mode);
      break;
  }
}

void FillQuad(GraphicsContext& context,
              const gfx::QuadF& quad,
              const Color& color,
              bool antialias,
              const AutoDarkMode& auto_dark_mode) {
  SkPath path;
  path.moveTo(gfx::PointFToSkPoint(quad.p1()));
  path.lineTo(gfx::PointFToSkPoint(quad.p2()));
  path.lineTo(gfx::PointFToSkPoint(quad.p3()));
  path.lineTo(gfx::PointFToSkPoint(quad.p4()));
  cc::PaintFlags flags(context.FillFlags());
  flags.setAntiAlias(antialias);
  flags.setColor(color.toSkColor4f());

  context.DrawPath(path, flags, auto_dark_mode);
}

void DrawSolidBoxSide(GraphicsContext& context,
                      int x1,
                      int y1,
                      int x2,
                      int y2,
                      BoxSide side,
                      Color color,
                      int adjacent_width1,
                      int adjacent_width2,
                      bool antialias,
                      const AutoDarkMode& auto_dark_mode) {
  DCHECK_GE(x2, x1);
  DCHECK_GE(y2, y1);

  if (!adjacent_width1 && !adjacent_width2) {
    // Tweak antialiasing to match the behavior of fillQuad();
    // this matters for rects in transformed contexts.
    bool was_antialiased = context.ShouldAntialias();
    if (antialias != was_antialiased)
      context.SetShouldAntialias(antialias);
    context.FillRect(gfx::Rect(x1, y1, x2 - x1, y2 - y1), color,
                     auto_dark_mode);
    if (antialias != was_antialiased)
      context.SetShouldAntialias(was_antialiased);
    return;
  }

  gfx::QuadF quad;
  switch (side) {
    case BoxSide::kTop:
      quad.set_p1(gfx::PointF(x1 + std::max(-adjacent_width1, 0), y1));
      quad.set_p2(gfx::PointF(x1 + std::max(adjacent_width1, 0), y2));
      quad.set_p3(gfx::PointF(x2 - std::max(adjacent_width2, 0), y2));
      quad.set_p4(gfx::PointF(x2 - std::max(-adjacent_width2, 0), y1));
      break;
    case BoxSide::kBottom:
      quad.set_p1(gfx::PointF(x1 + std::max(adjacent_width1, 0), y1));
      quad.set_p2(gfx::PointF(x1 + std::max(-adjacent_width1, 0), y2));
      quad.set_p3(gfx::PointF(x2 - std::max(-adjacent_width2, 0), y2));
      quad.set_p4(gfx::PointF(x2 - std::max(adjacent_width2, 0), y1));
      break;
    case BoxSide::kLeft:
      quad.set_p1(gfx::PointF(x1, y1 + std::max(-adjacent_width1, 0)));
      quad.set_p2(gfx::PointF(x1, y2 - std::max(-adjacent_width2, 0)));
      quad.set_p3(gfx::PointF(x2, y2 - std::max(adjacent_width2, 0)));
      quad.set_p4(gfx::PointF(x2, y1 + std::max(adjacent_width1, 0)));
      break;
    case BoxSide::kRight:
      quad.set_p1(gfx::PointF(x1, y1 + std::max(adjacent_width1, 0)));
      quad.set_p2(gfx::PointF(x1, y2 - std::max(adjacent_width2, 0)));
      quad.set_p3(gfx::PointF(x2, y2 - std::max(-adjacent_width2, 0)));
      quad.set_p4(gfx::PointF(x2, y1 + std::max(-adjacent_width1, 0)));
      break;
  }

  FillQuad(context, quad, color, antialias, auto_dark_mode);
}

void DrawLineForBoxSide(GraphicsContext& context,
                        int x1,
                        int y1,
                        int x2,
                        int y2,
                        BoxSide side,
                        Color color,
                        EBorderStyle style,
                        int adjacent_width1,
                        int adjacent_width2,
                        bool antialias,
                        const AutoDarkMode& auto_dark_mode) {
  int thickness;
  int length;
  if (side == BoxSide::kTop || side == BoxSide::kBottom) {
    thickness = y2 - y1;
    length = x2 - x1;
  } else {
    thickness = x2 - x1;
    length = y2 - y1;
  }

  // We would like this check to be an ASSERT as we don't want to draw empty
  // borders. However nothing guarantees that the following recursive calls to
  // DrawLineForBoxSide() will have positive thickness and length.
  if (length <= 0 || thickness <= 0) {
    return;
  }

  style = BorderEdge::EffectiveStyle(style, thickness);

  switch (style) {
    case EBorderStyle::kNone:
    case EBorderStyle::kHidden:
      return;
    case EBorderStyle::kDotted:
    case EBorderStyle::kDashed:
      DrawDashedOrDottedBoxSide(context, x1, y1, x2, y2, side, color, thickness,
                                style, antialias, auto_dark_mode);
      break;
    case EBorderStyle::kDouble:
      DrawDoubleBoxSide(context, x1, y1, x2, y2, length, side, color, thickness,
                        adjacent_width1, adjacent_width2, antialias,
                        auto_dark_mode);
      break;
    case EBorderStyle::kRidge:
    case EBorderStyle::kGroove:
      DrawRidgeOrGrooveBoxSide(context, x1, y1, x2, y2, side, color, style,
                               adjacent_width1, adjacent_width2, antialias,
                               auto_dark_mode);
      break;
    case EBorderStyle::kInset:
    case EBorderStyle::kOutset:
      color = CalculateBorderStyleColor(style, side, color);
      [[fallthrough]];
    case EBorderStyle::kSolid:
      DrawSolidBoxSide(context, x1, y1, x2, y2, side, color, adjacent_width1,
                       adjacent_width2, antialias, auto_dark_mode);
      break;
  }
}

void FindIntersection(const gfx::PointF& p1,
                      const gfx::PointF& p2,
                      const gfx::PointF& d1,
                      const gfx::PointF& d2,
                      gfx::PointF& intersection) {
  float px_length = p2.x() - p1.x();
  float py_length = p2.y() - p1.y();

  float dx_length = d2.x() - d1.x();
  float dy_length = d2.y() - d1.y();

  float denom = px_length * dy_length - py_length * dx_length;
  if (!denom)
    return;

  float param =
      ((d1.x() - p1.x()) * dy_length - (d1.y() - p1.y()) * dx_length) / denom;

  intersection.set_x(p1.x() + param * px_length);
  intersection.set_y(p1.y() + param * py_length);
}

}  // anonymous namespace

// Holds edges grouped by opacity and sorted in paint order.
struct BoxBorderPainter::ComplexBorderInfo {
  STACK_ALLOCATED();

 public:
  explicit ComplexBorderInfo(const BoxBorderPainter& border_painter) {
    Vector<BoxSide, 4> sorted_sides;

    // First, collect all visible sides.
    for (unsigned i = border_painter.first_visible_edge_; i < 4; ++i) {
      BoxSide side = static_cast<BoxSide>(i);

      if (IncludesEdge(border_pa
"""


```