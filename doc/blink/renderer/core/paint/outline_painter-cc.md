Response:
The user wants a summary of the `outline_painter.cc` file in Chromium's Blink rendering engine. I need to identify the main functionalities of this file based on the provided code. The key elements seem to be related to drawing outlines around elements, particularly focusing on different outline styles, handling rounded corners, and rendering the focus ring.

Here's a breakdown of the code's apparent purpose:

1. **Outline Painting:** The file seems responsible for drawing outlines for HTML elements. This involves:
    - Handling different outline styles (solid, double, dotted, dashed, groove, ridge, inset, outset).
    - Applying the `outline-width`, `outline-color`, and `outline-offset` CSS properties.
    - Supporting rounded corners for outlines.
    - Optimizations for specific outline styles (e.g., handling narrow double outlines).

2. **Focus Ring Painting:**  A significant part of the code deals with drawing the focus ring, a visual indicator when an element has focus. This includes:
    - Determining the thickness of the focus ring based on zoom level and platform settings.
    - Calculating the offset of the focus ring.
    - Handling rounded corners for the focus ring, potentially inheriting or adapting from the element's border-radius or the platform's default.
    - Drawing the focus ring as a single or double ring.

3. **Geometric Calculations:** The code performs various geometric calculations to determine the shape and position of the outlines:
    - Computing the path of the outline based on element rectangles and offsets.
    - Handling right-angled and rounded corners.
    - Adjusting the outline path for different styles.
    - Clipping operations to achieve the desired visual effect.

4. **Interaction with other Blink components:**  The file interacts with:
    - `ComputedStyle`: To get the CSS properties related to outlines.
    - `GraphicsContext`: To perform the actual drawing operations.
    - `LayoutObject`: To get the geometry of the element.
    - `NativeTheme`: To respect platform-specific styling for focus rings.

Based on this, I can now formulate a summary of the file's functionalities, highlighting its relationship with CSS, potential user errors, debugging aspects, and providing illustrative examples.
这是 Blink 渲染引擎中 `blink/renderer/core/paint/outline_painter.cc` 文件的第一部分，主要负责 **绘制 HTML 元素的轮廓 (outline)**。

以下是该部分代码的功能归纳：

**核心功能：**

1. **定义了 `OutlinePainter` 类及其相关辅助函数，用于绘制元素的轮廓。**  轮廓是围绕元素边框外部绘制的一条线。

2. **处理不同类型的轮廓样式 (outline-style):**
   - 支持 `solid` (实线), `double` (双线), `dotted` (点状线), `dashed` (虚线), `groove` (凹槽), `ridge` (凸起), `inset` (内凹), `outset` (外凸) 等样式。
   - 针对特定样式进行了优化，例如，对于较窄的 `double` 轮廓会调整为 `solid`。

3. **处理轮廓的宽度 (outline-width)、颜色 (outline-color) 和偏移 (outline-offset)。**

4. **支持为轮廓添加圆角。** 如果元素的 `border-radius` 属性被设置，轮廓也会呈现圆角。

5. **实现了绘制焦点环 (focus ring) 的功能。** 焦点环是当元素获得焦点时，浏览器在其周围绘制的视觉指示器。
   - 可以根据缩放级别动态调整焦点环的宽度。
   - 可以绘制单层或双层焦点环。
   - 考虑了平台特定的主题 (Native Theme) 来绘制焦点环，例如使用平台默认的焦点环样式和半径。

6. **使用 `GraphicsContext` 进行实际的绘制操作。**  `GraphicsContext` 是一个用于执行 2D 图形绘制的抽象接口。

7. **利用 `SkPath` 来构建轮廓的形状。** `SkPath` 是 Skia 图形库中的一个类，用于表示复杂的几何路径。

8. **包含一些辅助函数用于计算和调整轮廓的几何形状。**
   - 例如 `AdjustedOutlineOffset` 用于确保负的 `outline-offset` 不会导致轮廓过小。
   - `ComputeRightAnglePath` 用于计算由一组矩形构成的区域的外部轮廓路径。
   - `ShrinkRightAnglePath` 用于收缩直角路径。
   - `AddCornerRadiiToPath` 用于向直角路径添加圆角。

**与 JavaScript, HTML, CSS 的关系：**

- **CSS 属性：**  该代码直接响应 CSS 的轮廓相关属性，例如 `outline-style`, `outline-width`, `outline-color`, `outline-offset`, 以及间接响应 `border-radius`（影响轮廓的圆角）。
    - **举例：**
        - HTML: `<div style="outline: 2px solid blue; outline-offset: 5px;">...</div>`  这段 CSS 会导致该文件中的代码被调用，绘制一个 2 像素宽的蓝色实线轮廓，并向外偏移 5 像素。
        - HTML: `<button style="border-radius: 10px; outline: 3px dashed red;">Click Me</button>`  这段 CSS 会导致绘制一个红色虚线轮廓，并且轮廓的角是圆角的，圆角半径受到 `border-radius` 的影响。
        - 当用户通过 JavaScript 修改元素的 `style` 属性或添加/删除 CSS 类时，如果涉及到轮廓相关的属性，也会触发该文件的代码执行。

- **焦点环：** 当用户通过键盘 Tab 键导航或者点击可聚焦元素（例如按钮、输入框、链接）时，浏览器会绘制焦点环来指示当前聚焦的元素。这部分代码负责绘制这个焦点环。
    - **举例：** 用户在网页上按 Tab 键，焦点移动到一个按钮上，该按钮的样式中没有显式设置轮廓，但浏览器会根据默认样式或用户代理样式表绘制一个焦点环。 `OutlinePainter` 中的焦点环绘制逻辑就会被执行。

**逻辑推理 (假设输入与输出)：**

假设输入以下 CSS 样式和一个矩形区域：

```css
.element {
  width: 100px;
  height: 50px;
  outline: 4px double green;
  outline-offset: -2px;
  border-radius: 5px;
}
```

以及一个代表该元素的矩形区域 `rects = [{x: 10, y: 20, width: 100, height: 50}]`。

**可能的输出 (SkPath 形状，简化描述)：**

1. **`ComputeRightAnglePath` (或类似逻辑):**  会基于矩形区域和偏移量计算出一个初始的直角轮廓路径。由于 `outline-offset` 为负，轮廓会向内收缩。

2. **圆角处理:**  由于 `border-radius` 为 5px，代码会计算出合适的圆角半径，并修改初始的直角路径，使其四个角变为圆角。

3. **双线样式处理:**  由于 `outline-style` 是 `double`，代码会生成两条平行的路径来模拟双线效果。

4. **最终绘制:**  `GraphicsContext` 会使用计算出的 `SkPath` 和颜色（绿色）来绘制轮廓。

**用户或编程常见的使用错误：**

1. **错误的 `outline-offset` 使用：**  程序员可能会设置一个过大的负 `outline-offset`，期望轮廓完全绘制在元素内部，但这可能会导致意想不到的裁剪或重叠效果。代码中的 `AdjustedOutlineOffset` 函数会部分缓解这个问题，确保轮廓不会完全消失。

2. **与 `border` 属性的混淆：**  新手开发者可能会混淆 `outline` 和 `border` 属性。 `outline` 不占用布局空间，绘制在元素内容区域的外部，而 `border` 会占用布局空间。

3. **过度依赖默认焦点环样式：**  开发者可能没有充分考虑不同浏览器的默认焦点环样式可能不一致，导致在不同浏览器上看到不同的效果。建议为可聚焦元素提供自定义的焦点指示样式。

**用户操作是如何一步步的到达这里 (调试线索)：**

1. **用户加载网页：** 浏览器开始解析 HTML 和 CSS。
2. **渲染树构建：** Blink 引擎根据 HTML 和 CSS 构建渲染树。对于设置了 `outline` 属性或需要绘制焦点环的元素，会创建相应的渲染对象。
3. **布局计算：** 确定每个元素在页面上的位置和大小。
4. **绘制阶段：**
   - 当需要绘制一个设置了 `outline` 属性的元素时，或者当一个可聚焦元素获得焦点时，Blink 的绘制流程会调用到 `OutlinePainter::Paint` 或类似的函数。
   -  `PaintInfo` 结构体会传递有关绘制的上下文信息，包括 `GraphicsContext`。
   - `LayoutObject::OutlineInfo` 提供轮廓的样式、宽度和偏移等信息，这些信息来源于元素的 `ComputedStyle`。
   - `ComputedStyle` 则包含了元素最终生效的 CSS 属性值。
5. **执行 `outline_painter.cc` 中的代码：** 根据 `ComputedStyle` 中的轮廓属性值和元素的几何信息，计算并绘制轮廓或焦点环。

**总结该部分功能：**

总而言之，`blink/renderer/core/paint/outline_painter.cc` 的第一部分主要负责处理和绘制 HTML 元素的各种轮廓样式，包括根据 CSS 属性绘制普通轮廓，以及在元素获得焦点时绘制焦点环。它涉及到几何计算、图形绘制以及与 Blink 引擎其他组件的交互，例如 `ComputedStyle` 和 `GraphicsContext`。

Prompt: 
```
这是目录为blink/renderer/core/paint/outline_painter.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/outline_painter.h"

#include <optional>

#include "build/build_config.h"
#include "third_party/blink/renderer/core/layout/geometry/physical_rect.h"
#include "third_party/blink/renderer/core/paint/box_border_painter.h"
#include "third_party/blink/renderer/core/paint/paint_auto_dark_mode.h"
#include "third_party/blink/renderer/core/paint/paint_info.h"
#include "third_party/blink/renderer/core/paint/rounded_border_geometry.h"
#include "third_party/blink/renderer/core/style/border_edge.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/platform/graphics/color.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context_state_saver.h"
#include "third_party/blink/renderer/platform/graphics/paint/drawing_recorder.h"
#include "third_party/blink/renderer/platform/graphics/path.h"
#include "third_party/blink/renderer/platform/graphics/skia/skia_utils.h"
#include "third_party/blink/renderer/platform/graphics/stroke_data.h"
#include "third_party/blink/renderer/platform/graphics/styled_stroke_data.h"
#include "ui/gfx/geometry/point_conversions.h"
#include "ui/gfx/geometry/rect.h"
#include "ui/gfx/geometry/skia_conversions.h"
#include "ui/native_theme/native_theme.h"

namespace blink {

namespace {

float FocusRingStrokeWidth(const ComputedStyle& style) {
  DCHECK(style.OutlineStyleIsAuto());
  // Draw focus ring with thickness in proportion to the zoom level, but never
  // so narrow that it becomes invisible.
  float width = 3.f;
  if (style.EffectiveZoom() >= 1.0f) {
    width = ui::NativeTheme::GetInstanceForWeb()->AdjustBorderWidthByZoom(
        width, style.EffectiveZoom());
    DCHECK_GE(width, 3.f);
  }
  return std::max(style.EffectiveZoom(), width);
}

float FocusRingOuterStrokeWidth(const ComputedStyle& style) {
  // The focus ring is made of two rings which have a 2:1 ratio.
  return FocusRingStrokeWidth(style) / 3.f * 2;
}

float FocusRingInnerStrokeWidth(const ComputedStyle& style) {
  return FocusRingStrokeWidth(style) / 3.f;
}

int FocusRingOffset(const ComputedStyle& style,
                    const LayoutObject::OutlineInfo& info) {
  DCHECK(style.OutlineStyleIsAuto());
  // How much space the focus ring would like to take from the actual border.
  const float max_inside_border_width =
      ui::NativeTheme::GetInstanceForWeb()->AdjustBorderWidthByZoom(
          1.0f, style.EffectiveZoom());
  int offset = info.offset;
  // Focus ring is dependent on whether the border is large enough to have an
  // inset outline. Use the smallest border edge for that test.
  float min_border_width =
      std::min({style.BorderTopWidth(), style.BorderBottomWidth(),
                style.BorderLeftWidth(), style.BorderRightWidth()});
  if (min_border_width >= max_inside_border_width)
    offset -= max_inside_border_width;
  return offset;
}

// A negative outline-offset should not cause the rendered outline shape to
// become smaller than twice the computed value of the outline-width, in each
// direction separately. See: https://drafts.csswg.org/css-ui/#outline-offset
gfx::Outsets AdjustedOutlineOffset(const gfx::Rect& rect, int offset) {
  return gfx::Outsets::VH(std::max(offset, -rect.height() / 2),
                          std::max(offset, -rect.width() / 2));
}

// Construct a clockwise path along the outer edge of the region covered by
// |rects| expanded by |outline_offset| (which can be negative and clamped by
// the rect size) and |additional_outset| (which should be non-negative).
bool ComputeRightAnglePath(SkPath& path,
                           const Vector<gfx::Rect>& rects,
                           int outline_offset,
                           int additional_outset) {
  DCHECK_GE(additional_outset, 0);
  SkRegion region;
  for (auto& r : rects) {
    gfx::Rect rect = r;
    rect.Outset(AdjustedOutlineOffset(rect, outline_offset));
    rect.Outset(additional_outset);
    region.op(gfx::RectToSkIRect(rect), SkRegion::kUnion_Op);
  }
  return region.getBoundaryPath(&path);
}

using Line = OutlinePainter::Line;

// Merge line2 into line1 if they are in the same straight line.
bool MergeLineIfPossible(Line& line1, const Line& line2) {
  DCHECK(line1.end == line2.start);
  if ((line1.start.x() == line1.end.x() && line1.start.x() == line2.end.x()) ||
      (line1.start.y() == line1.end.y() && line1.start.y() == line2.end.y())) {
    line1.end = line2.end;
    return true;
  }
  return false;
}

// Iterate a right angle |path| by running |contour_action| on each contour.
// The path contains one or more contours each of which is like (kMove_Verb,
// kLine_Verb, ..., kClose_Verb). Each line must be either horizontal or
// vertical. Each pair of adjacent lines (including the last and the first)
// should either create a right angle or be in the same straight line.
template <typename Action>
void IterateRightAnglePath(const SkPath& path, const Action& contour_action) {
  SkPath::Iter iter(path, /*forceClose*/ true);
  SkPoint points[4];
  Vector<Line> lines;
  for (SkPath::Verb verb = iter.next(points); verb != SkPath::kDone_Verb;
       verb = iter.next(points)) {
    switch (verb) {
      case SkPath::kMove_Verb:
        DCHECK(lines.empty());
        break;
      case SkPath::kLine_Verb: {
        Line new_line{points[0], points[1]};
        if (lines.empty() || !MergeLineIfPossible(lines.back(), new_line)) {
          lines.push_back(new_line);
          DCHECK(lines.size() == 1 ||
                 lines.back().start == lines[lines.size() - 2].end);
        }
        break;
      }
      case SkPath::kClose_Verb: {
        if (lines.size() >= 4u) {
          if (MergeLineIfPossible(lines.back(), lines.front())) {
            lines.front() = lines.back();
            lines.pop_back();
          }
          DCHECK(lines.front().start == lines.back().end);
          // lines.size() < 4 means that the contour is collapsed (i.e. the area
          // in the contour is empty). Ignore it.
          if (lines.size() >= 4u)
            contour_action(lines);
        }
        lines.clear();
        break;
      }
      default:
        NOTREACHED();
    }
  }
}

// Given 3 points defining a right angle corner, returns |p2| shifted to make
// the containing path shrunk by |inset|.
SkPoint ShrinkCorner(const SkPoint& p1,
                     const SkPoint& p2,
                     const SkPoint& p3,
                     int inset) {
  if (p1.x() == p2.x()) {
    if (p1.y() < p2.y()) {
      return p2.x() < p3.x() ? p2 + SkVector::Make(-inset, inset)
                             : p2 + SkVector::Make(-inset, -inset);
    }
    return p2.x() < p3.x() ? p2 + SkVector::Make(inset, inset)
                           : p2 + SkVector::Make(inset, -inset);
  }
  if (p1.x() < p2.x()) {
    return p2.y() < p3.y() ? p2 + SkVector::Make(-inset, inset)
                           : p2 + SkVector::Make(inset, inset);
  }
  return p2.y() < p3.y() ? p2 + SkVector::Make(-inset, -inset)
                         : p2 + SkVector::Make(inset, -inset);
}

void ShrinkRightAnglePath(SkPath& path, int inset) {
  SkPath input;
  std::swap(input, path);
  IterateRightAnglePath(input, [&path, inset](const Vector<Line>& lines) {
    for (wtf_size_t i = 0; i < lines.size(); i++) {
      const SkPoint& prev_point =
          lines[i == 0 ? lines.size() - 1 : i - 1].start;
      SkPoint new_point =
          ShrinkCorner(prev_point, lines[i].start, lines[i].end, inset);
      if (i == 0) {
        path.moveTo(new_point);
      } else {
        path.lineTo(new_point);
      }
    }
    path.close();
  });
}

FloatRoundedRect::Radii ComputeCornerRadii(
    const ComputedStyle& style,
    const PhysicalRect& reference_border_rect,
    float offset) {
  return RoundedBorderGeometry::PixelSnappedRoundedBorderWithOutsets(
             style, reference_border_rect, PhysicalBoxStrut(LayoutUnit(offset)))
      .GetRadii();
}

// Given 3 points defining a right angle corner, returns the corresponding
// corner in |convex_radii| or |concave_radii|.
gfx::SizeF GetRadiiCorner(const FloatRoundedRect::Radii& convex_radii,
                          const FloatRoundedRect::Radii& concave_radii,
                          const SkPoint& p1,
                          const SkPoint& p2,
                          const SkPoint& p3) {
  if (p1.x() == p2.x()) {
    if (p1.y() == p2.y() || p2.x() == p3.x())
      return gfx::SizeF();
    DCHECK_EQ(p2.y(), p3.y());
    if (p1.y() < p2.y()) {
      return p2.x() < p3.x() ? concave_radii.BottomLeft()
                             : convex_radii.BottomRight();
    }
    return p2.x() < p3.x() ? convex_radii.TopLeft() : concave_radii.TopRight();
  }
  DCHECK_EQ(p1.y(), p2.y());
  if (p2.x() != p3.x() || p2.y() == p3.y())
    return gfx::SizeF();
  if (p1.x() < p2.x()) {
    return p2.y() < p3.y() ? convex_radii.TopRight()
                           : concave_radii.BottomRight();
  }
  return p2.y() < p3.y() ? concave_radii.TopLeft() : convex_radii.BottomLeft();
}

// Shorten |line| between rounded corners.
void AdjustLineBetweenCorners(Line& line,
                              const FloatRoundedRect::Radii& convex_radii,
                              const FloatRoundedRect::Radii& concave_radii,
                              const SkPoint& prev_point,
                              const SkPoint& next_point) {
  gfx::SizeF corner1 = GetRadiiCorner(convex_radii, concave_radii, prev_point,
                                      line.start, line.end);
  gfx::SizeF corner2 = GetRadiiCorner(convex_radii, concave_radii, line.start,
                                      line.end, next_point);
  if (line.start.x() == line.end.x()) {
    // |line| is vertical, and adjacent lines are horizontal.
    float height = std::abs(line.end.y() - line.start.y());
    float corner1_height = corner1.height();
    float corner2_height = corner2.height();
    if (corner1_height + corner2_height > height) {
      // Scale down the corner heights to make the corners fit in |height|.
      float scale = height / (corner1_height + corner2_height);
      corner1_height = floorf(corner1_height * scale);
      corner2_height = floorf(corner2_height * scale);
    }
    if (line.start.y() < line.end.y()) {
      line.start.offset(0, corner1_height);
      line.end.offset(0, -corner2_height);
    } else {
      line.start.offset(0, -corner1_height);
      line.end.offset(0, corner2_height);
    }
  } else {
    // |line| is horizontal, and adjacent lines are vertical.
    float width = std::abs(line.end.x() - line.start.x());
    float corner1_width = corner1.width();
    float corner2_width = corner2.width();
    if (corner1_width + corner2_width > width) {
      // Scale down the corner widths to make the corners fit in |width|.
      float scale = width / (corner1_width + corner2_width);
      corner1_width = floorf(corner1_width * scale);
      corner2_width = floorf(corner2_width * scale);
    }
    if (line.start.x() < line.end.x()) {
      line.start.offset(corner1_width, 0);
      line.end.offset(-corner2_width, 0);
    } else {
      line.start.offset(-corner1_width, 0);
      line.end.offset(corner2_width, 0);
    }
  }
}

// The weight of SkPath::conicTo() to create a 90deg rounded corner arc.
constexpr float kCornerConicWeight = 0.707106781187;  // 1/sqrt(2)

// Create a rounded path from a right angle |path| by
// - inserting arc segments for corners;
// - adjusting length of the lines.
void AddCornerRadiiToPath(SkPath& path,
                          const FloatRoundedRect::Radii& convex_radii,
                          const FloatRoundedRect::Radii& concave_radii) {
  SkPath input;
  input.swap(path);
  IterateRightAnglePath(input, [&](const Vector<Line>& lines) {
    auto new_lines = lines;
    for (wtf_size_t i = 0; i < lines.size(); i++) {
      const SkPoint& prev_point =
          lines[i == 0 ? lines.size() - 1 : i - 1].start;
      const SkPoint& next_point = lines[i == lines.size() - 1 ? 0 : i + 1].end;
      AdjustLineBetweenCorners(new_lines[i], convex_radii, concave_radii,
                               prev_point, next_point);
    }
    // Generate the new contour into |path|.
    DCHECK_EQ(lines.size(), new_lines.size());
    path.moveTo(new_lines.back().end);
    for (wtf_size_t i = 0; i < new_lines.size(); i++) {
      // Keep empty arcs and lines to allow RoundedEdgePathIterator to match
      // edges. Produce a 90 degree arc from the current point (end of the
      // previous line) towards lines[i].start to new_lines[i].start.
      path.conicTo(lines[i].start, new_lines[i].start, kCornerConicWeight);
      path.lineTo(new_lines[i].end);
    }
    path.close();
  });
}

// Move |point| so that the length of the line to |other| will be extended by
// |offset|.
void ExtendLineAtEndpoint(SkPoint& point, const SkPoint& other, int offset) {
  if (point.x() == other.x()) {
    point.offset(0, point.y() < other.y() ? -offset : offset);
  } else {
    DCHECK_EQ(point.y(), other.y());
    point.offset(point.x() < other.x() ? -offset : offset, 0);
  }
}

// Iterates a rounded outline center path, and for each edge [1] returns the
// path that can be used to stroke the edge.
// [1] An "edge" means a segment of the path, including a horizontal or vertical
// line and approximate halves of its adjacent arcs if any.
class RoundedEdgePathIterator {
  STACK_ALLOCATED();

 public:
  RoundedEdgePathIterator(const SkPath& rounded_center_path, int center_inset)
      : iter_(rounded_center_path, /*forceClose*/ true),
        center_inset_(center_inset) {}

  SkPath Next() {
    SkPath edge_stroke_path;
    while (true) {
      SkPoint points[4];
      switch (iter_.next(points)) {
        case SkPath::kConic_Verb:
          if (is_new_contour_) {
            std::copy_n(points, kArcPointCount, prev_arc_points_);
            std::copy_n(points, kArcPointCount, first_arc_points_);
            is_new_contour_ = false;
            continue;
          }
          GenerateEdgeStrokePath(edge_stroke_path, prev_arc_points_, points);
          std::copy_n(points, kArcPointCount, prev_arc_points_);
          return edge_stroke_path;
        case SkPath::kClose_Verb:
          DCHECK(!is_new_contour_);
          GenerateEdgeStrokePath(edge_stroke_path, prev_arc_points_,
                                 first_arc_points_);
          is_new_contour_ = true;
          return edge_stroke_path;
        case SkPath::kDone_Verb:
          return edge_stroke_path;
        default:
          continue;
      }
    }
  }

 private:
  // An example of an edge stroke path:
  // |             Short extension before the starting arc (see code comment)
  //  \            Starting arc
  //   \______     Line
  //          \    Ending arc
  //           |   Short extension after the ending arc (see code comment)
  // The edge will drawn with a clip to remove the first half of the starting
  // arc and the second half of the ending arc.
  void GenerateEdgeStrokePath(SkPath& edge_stroke_path,
                              base::span<const SkPoint> starting_arc_points,
                              base::span<const SkPoint> ending_arc_points) {
    SkPoint line_start = starting_arc_points[2];
    SkPoint line_end = ending_arc_points[0];
    if (starting_arc_points[0] == line_start) {
      // No starting arc. Extend the line to fill the miter.
      ExtendLineAtEndpoint(line_start, ending_arc_points[1], center_inset_);
      edge_stroke_path.moveTo(line_start);
    } else {
      SkPoint start = starting_arc_points[0];
      // Add a short line before the arc in case the starting arc is too short
      // to fill the miter.
      ExtendLineAtEndpoint(start, starting_arc_points[1], center_inset_);
      edge_stroke_path.moveTo(start);
      edge_stroke_path.lineTo(starting_arc_points[0]);
      edge_stroke_path.conicTo(starting_arc_points[1], line_start,
                               kCornerConicWeight);
    }
    if (line_end == ending_arc_points[2]) {
      // No ending arc. Extend the line to fill the miter.
      ExtendLineAtEndpoint(line_end, starting_arc_points[1], center_inset_);
      edge_stroke_path.lineTo(line_end);
    } else {
      edge_stroke_path.lineTo(line_end);
      SkPoint end = ending_arc_points[2];
      edge_stroke_path.conicTo(ending_arc_points[1], end, kCornerConicWeight);
      // Add a short line after the ending arc in case the arc is too short to
      // fill the miter.
      ExtendLineAtEndpoint(end, ending_arc_points[1], center_inset_);
      edge_stroke_path.lineTo(end);
    }
  }

  SkPath::Iter iter_;
  const int center_inset_;
  bool is_new_contour_ = true;
  // The three points are: start, control (the right-angle corner), end.
  static constexpr size_t kArcPointCount = 3;
  SkPoint first_arc_points_[kArcPointCount];
  SkPoint prev_arc_points_[kArcPointCount];
};

class ComplexOutlinePainter {
  STACK_ALLOCATED();

 public:
  ComplexOutlinePainter(GraphicsContext& context,
                        const Vector<gfx::Rect>& rects,
                        const PhysicalRect& reference_border_rect,
                        const ComputedStyle& style,
                        const LayoutObject::OutlineInfo& info)
      : context_(context),
        rects_(rects),
        reference_border_rect_(reference_border_rect),
        style_(style),
        outline_style_(style.OutlineStyle()),
        offset_(info.offset),
        width_(info.width),
        color_(style.VisitedDependentColor(GetCSSPropertyOutlineColor())),
        is_rounded_(style.HasBorderRadius()) {
    DCHECK(!style.OutlineStyleIsAuto());
    DCHECK_NE(width_, 0);
    if (width_ <= 2 && outline_style_ == EBorderStyle::kDouble) {
      outline_style_ = EBorderStyle::kSolid;
    } else if (width_ == 1 && (outline_style_ == EBorderStyle::kRidge ||
                               outline_style_ == EBorderStyle::kGroove)) {
      outline_style_ = EBorderStyle::kSolid;
      Color dark = color_.Dark();
      color_ = Color(
          (color_.Red() + dark.Red()) / 2, (color_.Green() + dark.Green()) / 2,
          (color_.Blue() + dark.Blue()) / 2, color_.AlphaAsInteger());
    }
  }

  void Paint() {
    if (!ComputeRightAnglePath(right_angle_outer_path_, rects_, offset_,
                               width_)) {
      return;
    }

    bool use_alpha_layer = !color_.IsOpaque() &&
                           outline_style_ != EBorderStyle::kSolid &&
                           outline_style_ != EBorderStyle::kDouble;
    if (use_alpha_layer) {
      context_.BeginLayer(color_.Alpha());
      color_ = Color::FromRGB(color_.Red(), color_.Green(), color_.Blue());
    }

    SkPath outer_path = right_angle_outer_path_;
    SkPath inner_path = right_angle_outer_path_;
    ShrinkRightAnglePath(inner_path, width_);
    if (is_rounded_) {
      auto inner_radii = ComputeRadii(0);
      auto outer_radii = ComputeRadii(width_);
      AddCornerRadiiToPath(outer_path, outer_radii, inner_radii);
      AddCornerRadiiToPath(inner_path, inner_radii, outer_radii);
    }

    GraphicsContextStateSaver saver(context_);
    context_.ClipPath(outer_path, kAntiAliased);
    MakeClipOutPath(inner_path);
    context_.ClipPath(inner_path, kAntiAliased);
    context_.SetFillColor(color_);

    switch (outline_style_) {
      case EBorderStyle::kSolid:
        context_.FillRect(
            gfx::SkRectToRectF(outer_path.getBounds()),
            PaintAutoDarkMode(style_,
                              DarkModeFilter::ElementRole::kBackground));
        break;
      case EBorderStyle::kDouble:
        PaintDoubleOutline();
        break;
      case EBorderStyle::kDotted:
      case EBorderStyle::kDashed:
        PaintDottedOrDashedOutline();
        break;
      case EBorderStyle::kGroove:
      case EBorderStyle::kRidge:
        PaintGrooveOrRidgeOutline();
        break;
      case EBorderStyle::kInset:
      case EBorderStyle::kOutset:
        PaintInsetOrOutsetOutline(CenterPath(),
                                  outline_style_ == EBorderStyle::kInset);
        break;
      default:
        NOTREACHED();
    }

    if (use_alpha_layer)
      context_.EndLayer();
  }

 private:
  void PaintDoubleOutline() {
    SkPath inner_third_path = right_angle_outer_path_;
    SkPath outer_third_path = right_angle_outer_path_;
    int stroke_width = std::round(width_ / 3.0);
    ShrinkRightAnglePath(inner_third_path, width_ - stroke_width);
    ShrinkRightAnglePath(outer_third_path, stroke_width);
    if (is_rounded_) {
      auto inner_third_radii = ComputeRadii(stroke_width);
      auto outer_third_radii = ComputeRadii(width_ - stroke_width);
      AddCornerRadiiToPath(inner_third_path, inner_third_radii,
                           outer_third_radii);
      AddCornerRadiiToPath(outer_third_path, outer_third_radii,
                           inner_third_radii);
    }
    AutoDarkMode auto_dark_mode(
        PaintAutoDarkMode(style_, DarkModeFilter::ElementRole::kBackground));
    context_.FillPath(inner_third_path, auto_dark_mode);
    MakeClipOutPath(outer_third_path);
    context_.ClipPath(outer_third_path, kAntiAliased);
    context_.FillRect(gfx::SkRectToRectF(right_angle_outer_path_.getBounds()),
                      auto_dark_mode);
  }

  void PaintDottedOrDashedOutline() {
    auto stroke_style =
        outline_style_ == EBorderStyle::kDashed ? kDashedStroke : kDottedStroke;
    StyledStrokeData styled_stroke;
    styled_stroke.SetStyle(stroke_style);
    if ((width_ % 2) &&
        StyledStrokeData::StrokeIsDashed(width_, stroke_style)) {
      // If width_ is odd, draw wider to fill the clip area.
      styled_stroke.SetThickness(width_ + 2);
    } else {
      styled_stroke.SetThickness(width_);
    }
    context_.SetStrokeColor(color_);

    SkPath center_path = CenterPath();
    AutoDarkMode auto_dark_mode(
        PaintAutoDarkMode(style_, DarkModeFilter::ElementRole::kBackground));
    if (is_rounded_) {
      const Path path(center_path);
      const StrokeData stroke_data = styled_stroke.ConvertToStrokeData(
          {static_cast<int>(path.length()), width_, path.IsClosed()});
      context_.SetStroke(stroke_data);
      context_.StrokePath(path, auto_dark_mode);
    } else {
      // Draw edges one by one instead of the whole path to let the corners
      // have starting/ending dots/dashes.
      IterateRightAnglePath(
          center_path,
          [this, &styled_stroke, &auto_dark_mode](const Vector<Line>& lines) {
            for (const auto& line : lines) {
              PaintStraightEdge(line, styled_stroke, auto_dark_mode);
            }
          });
    }
  }

  void PaintGrooveOrRidgeOutline() {
    SkPath center_path = CenterPath();
    // Paint the whole outline, treating kGroove as kInset.
    PaintInsetOrOutsetOutline(center_path,
                              outline_style_ == EBorderStyle::kGroove);
    // Paint dark color in the inner half.
    context_.ClipPath(center_path, kAntiAliased);
    context_.SetStrokeColor(color_.Dark());
    PaintTopLeftOrBottomRight(center_path,
                              outline_style_ == EBorderStyle::kRidge);
    // Paint light color in the inner half. If width_ is odd, draw thinner
    // (by preferring outer half) because light color looks wider.
    if (width_ % 2) {
      SkPath center_path_prefer_outer = CenterPath(/*prefer_outer*/ true);
      context_.ClipPath(center_path_prefer_outer, kAntiAliased);
    }
    context_.SetStrokeColor(color_);
    PaintTopLeftOrBottomRight(center_path,
                              outline_style_ == EBorderStyle::kGroove);
  }

  void PaintInsetOrOutsetOutline(const SkPath& center_path, bool is_inset) {
    context_.SetStrokeColor(color_);
    PaintTopLeftOrBottomRight(center_path, !is_inset);
    context_.SetStrokeColor(color_.Dark());
    PaintTopLeftOrBottomRight(center_path, is_inset);
  }

  void PaintTopLeftOrBottomRight(const SkPath& center_path,
                                 bool top_left_or_bottom_right) {
    StyledStrokeData styled_stroke;
    // If width_ is odd, draw wider to fill the clip area.
    styled_stroke.SetThickness(width_ % 2 ? width_ + 2 : width_);
    std::optional<RoundedEdgePathIterator> rounded_edge_path_iterator;
    if (is_rounded_)
      rounded_edge_path_iterator.emplace(center_path, (width_ + 1) / 2);
    AutoDarkMode auto_dark_mode(
        PaintAutoDarkMode(style_, DarkModeFilter::ElementRole::kBackground));
    IterateRightAnglePath(
        is_rounded_ ? right_angle_outer_path_ : center_path,
        [this, top_left_or_bottom_right, &rounded_edge_path_iterator,
         &styled_stroke, &auto_dark_mode](const Vector<Line>& lines) {
          for (wtf_size_t i = 0; i < lines.size(); i++) {
            const Line& line = lines[i];
            std::optional<SkPath> rounded_edge_path;
            if (rounded_edge_path_iterator)
              rounded_edge_path = rounded_edge_path_iterator->Next();
            bool is_top_or_left =
                line.start.x() < line.end.x() || line.start.y() > line.end.y();
            if (is_top_or_left != top_left_or_bottom_right)
              continue;
            const Line& prev_line = lines[i == 0 ? lines.size() - 1 : i - 1];
            const Line& next_line = lines[i == lines.size() - 1 ? 0 : i + 1];
            GraphicsContextStateSaver clip_saver(context_);
            context_.ClipPath(
                MiterClipPath(prev_line.start, line, next_line.end),
                kNotAntiAliased);
            if (is_rounded_) {
              context_.SetStrokeThickness(styled_stroke.Thickness());
              context_.StrokePath(*rounded_edge_path, auto_dark_mode);
            } else {
              PaintStraightEdge(line, styled_stroke, auto_dark_mode);
            }
          }
        });
  }

  void MakeClipOutPath(SkPath& path) const {
    // Add a counter-clockwise rect around the path, so that with kWinding fill
    // type:
    // 1. the areas enclosed in clockwise boundaries become "out",
    // 2. the areas outside of the original path become "in", and
    // 3. the areas enclosed in counter-clockwise boundaries are still "in".
    // This is different from kInverseWinding or GraphicsContext::ClipOut()
    // in #3, which is important not to clip out the areas enclosed by crossing
    // edges produced when shrinking from the outer path.
    DCHECK_EQ(path.getFillType(), SkPathFillType::kWinding);
    path.addRect(right_angle_outer_path_.getBounds(), SkPathDirection::kCCW);
  }

  FloatRoundedRect::Radii ComputeRadii(int outset) const {
    DCHECK(is_rounded_);
    return ComputeCornerRadii(style_, reference_border_rect_, offset_ + outset);
  }

  SkPath CenterPath(bool prefer_outer_half = false) const {
    SkPath center_path = right_angle_outer_path_;
    // If |prefer_outer_half| and width_ is odd_, give the outer half 1 more
    // pixel than the inner half.
    int outset_from_inner = prefer_outer_half ? width_ / 2 : (width_ + 1) / 2;
    ShrinkRightAnglePath(center_path, width_ - outset_from_inner);
    if (is_rounded_) {
      auto center_radii = ComputeRadii(outset_from_inner);
      AddCornerRadiiToPath(center_path, center_radii, center_radii);
    }
    return center_path;
  }

  static int MiterSlope(const SkPoint& p1,
                        const SkPoint& p2,
                        const SkPoint& p3) {
    if (p1.x() == p2.x())
      return (p3.x() > p2.x()) == (p2.y() > p1.y()) ? 1 : -1;
    return (p3.y() > p2.y()) == (p2.x() > p1.x()) ? 1 : -1;
  }

  // Apply clip to remove the extra part of an edge exceeding the miters
  // (formed by 45deg divisions between edges, across the rounded or right-angle
  // corners). The clip should be big enough to include rounded corners within
  // the miters.
  SkPath MiterClipPath(const SkPoint& prev_point,
                       const Line& line,
                       const SkPoint& next_point) const {
    SkRect bounds = right_angle_outer_path_.getBounds();
    int start_miter_slope = MiterSlope(prev_point, line.start, line.end);
    int end_miter_slope = MiterSlope(line.start, line.end, next_point);
    SkPoint p1 = SkPoint::Make(
        line.start.x() + start_miter_slope * (line.start.y() - bounds.top()),
        bounds.top());
    SkPoint p2 = SkPoint::Make(
        line.end.x() + end_miter_slope * (line.end.y() - bounds.top()),
        bounds.top());
    SkPoint p3 = SkPoint::Make(
        line.end.x() - end_miter_slope * (bounds.bottom() - line.end.y()),
        bounds.bottom());
    SkPoint p4 = SkPoint::Make(
        line.start.x() - start_miter_slope * (bounds.bottom() - line.start.y()),
        bounds.bottom());
    // If start_miter_slope == end_miter_slope, the clip path is a parallelogram
    // which is good for both horizontal and vertical edges. Otherwise the path
    // is a trapezoid or a butterfly quadrilateral, and a vertical edge is
    // outside of the path.
    auto path = SkPath::Polygon({p1, p2, p3, p4}, /*isClosed*/ true);
    if (start_miter_slope != end_miter_slope && line.start.x() == line.end.x())
      path.setFillType(SkPathFillType::kInverseWinding);
    return path;
  }

  void PaintStraightEdge(const Line& line,
                         const StyledStrokeData& styled_stroke,
                         const AutoDarkMode& auto_dark_mode) {
    Line adjusted_line = line;
    // GraphicsContext::DrawLine requires the line to be top-to-down or
    // left-to-right get correct interval among dots/dashes.
    if (line.start.x() > line.end.x() || line.start.y() > line.end.y())
      std::swap(adjusted_line.start, adjusted_line.end);
    // Extend the line to fully cover the corners at both endpoints.
    int joint_offset = (width_ + 1) / 2;
    ExtendLineAtEndpoint(adjusted_line.start, adjusted_line.end, joint_offset);
    ExtendLineAtEndpoint(adjusted_line.end, adjusted_line.start, joint_offset);
    context_.DrawLine(
        gfx::ToRoundedPoint(gfx::SkPointToPointF(adjusted_line.start)),
        gfx::ToRoundedPoint(gfx::SkPointToPointF(adjusted_line.end)),
        styled_stroke, auto_dark_mode);
  }

  GraphicsContext& context_;
  const Vector<gfx::Rect>& rects_;
  const PhysicalRect& reference_border_rect_;
  const ComputedStyle& style_;
  EBorderStyle outline_style_;
  int offset_;
  int width_;
  Color color_;
  bool is_rounded_;
  SkPath right_angle_outer_path_;
};

float DefaultFocusRingCornerRadius(const ComputedStyle& style) {
  // Default style is corner radius equal to outline width.
  return FocusRingStrokeWidth(style);
}

FloatRoundedRect::Radii GetFocusRingCornerRadii(
    const ComputedStyle& style,
    const PhysicalRect& reference_border_rect,
    const LayoutObject::OutlineInfo& info) {
  if (style.HasBorderRadius() &&
      (!style.HasEffectiveAppearance() || style.HasAuthorBorderRadius())) {
    auto radii = ComputeCornerRadii(style, reference_border_rect, info.offset);
    radii.SetMinimumRadius(DefaultFocusRingCornerRadius(style));
    return radii;
  }

  if (!style.HasAuthorBorder() && style.HasEffectiveAppearance()) {
    // For the elements that have not been styled and that have an appearance,
    // the focus ring should use the same border radius as the one used for
    // drawing the element.
    std::optional<ui::NativeTheme::Part> part;
    switch (style.EffectiveAppearance()) {
      case kCheckboxPart:
        part = ui::NativeTheme::kCheckbox;
        break;
      case kRadioPart:
        part = ui::NativeTheme::kRadio;
        break;
      case kPushButtonPart:
      case kSquareButtonPart:
      case kButtonPart:
        part = ui::NativeTheme::kPushButton;
        break;
      case kTextFieldPart:
      case kTextAreaPart:
      case kSearchFieldPart:
        part = ui::NativeTheme::kTextField;
        break;
      default:
        break;
    }
    if (part) {
      float corner_radius =
          ui::NativeTheme::GetInstanceForWeb()->GetBorderRadiusForPart(
              part.value(), reference_border_rect.size.width,
              reference_border_rect.size.height);
      corner_radius =
          ui::NativeTheme::GetInstanceForWeb()->AdjustBorderRadiusByZoom(
              part.value(), corner_radius, style.EffectiveZoom());
      return FloatRoundedRect::Radii(corner_radius);
    }
  }

  return FloatRoundedRect::Radii(DefaultFocusRingCornerRadius(style));
}

void PaintSingleFocusRing(GraphicsContext& context,
                          const Vector<gfx::Rect>& rects,
                          float width,
                          int offset,
                          const FloatRoundedRect::Radii& corner_
"""


```