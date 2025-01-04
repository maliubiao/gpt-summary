Response:
The user wants a summary of the functionality of the `box_border_painter.cc` file in the Chromium Blink rendering engine. This is the second part of a three-part request. I need to focus on summarizing the features presented in the provided code snippet.

The code snippet primarily deals with drawing borders with various styles, colors, and opacities. It handles both simple and complex border rendering scenarios, including rounded borders and borders with transparency. The code also introduces the concept of opacity groups to optimize the rendering of translucent borders.

Here's a breakdown of the key components:

1. **Sorting Border Sides:** The code sorts the visible border sides based on their alpha, style, and side priority to determine the painting order.
2. **Opacity Grouping:** It groups border sides with the same opacity level.
3. **Drawing Double Borders:**  Specific logic for drawing double borders.
4. **Fast Path Optimization:**  A faster rendering path for simple, uniform borders.
5. **Complex Border Painting:**  Handles more complex borders, including those with transparency and rounded corners, by leveraging opacity groups and layering.
6. **Painting Individual Sides:**  Functions to draw each side of the border, taking into account miters and potential clipping.
7. **Path-Based Rendering:**  Uses paths for rendering more complex border styles and rounded corners.
8. **Dashed and Dotted Borders:**  Specific rendering logic for dashed and dotted borders, including handling wide dotted borders.
9. **Ridge and Groove Borders:**  Special rendering for ridge and groove border styles.
10. **Miter Calculation and Handling:**  Determines how corners should be rendered (mitered or not) based on style and color.
11. **Clipping:**  Uses clipping to create miters and handle certain border styles.

Therefore, the primary function is to **render the borders of HTML elements**, taking into account various CSS border properties like `border-style`, `border-width`, `border-color`, `border-radius`, and `opacity`.
这是`blink/renderer/core/paint/box_border_painter.cc`文件的第二部分代码，主要功能是**处理复杂和具有透明度的边框绘制**。

在前一部分，可能已经处理了简单、统一的边框绘制逻辑。这部分代码则专注于处理以下情况：

* **边框具有不同的透明度 (alpha):**  它会将具有相同透明度的边框边组合成“透明度组 (Opacity Groups)”，并根据透明度进行排序，以便正确地绘制具有不同透明度的边框，避免出现不期望的重叠或混合效果。
* **复杂的边框样式:** 当边框不是统一的颜色或样式时，需要更精细的绘制逻辑，例如虚线、点线、双线以及 ridge 和 groove 样式在圆角边框上的绘制。
* **圆角边框 (rounded borders):**  代码使用 `Path` 对象来描述圆角边框的形状，并利用路径进行绘制或裁剪。
* **优化具有透明度的边框绘制:** 通过使用图层 (layers) 和调整不透明度，确保透明边框的正确渲染，并尝试利用重叠绘制 (overdraw) 来优化性能。

**与 JavaScript, HTML, CSS 的关系举例说明:**

* **CSS 属性:** 代码直接对应于 CSS 的边框相关属性，例如 `border-top-color`, `border-right-style`, `border-width`, `border-radius`, `opacity` 等。
    * **假设输入 (CSS):**  一个 `div` 元素设置了如下 CSS:
      ```css
      div {
        border-top: 2px solid red;
        border-right: 3px dashed blue;
        border-bottom: 4px dotted green;
        border-left: 5px double black;
        border-radius: 10px;
        opacity: 0.5; /* 应用于整个元素，包括边框 */
      }
      ```
    * **功能体现:** `BoxBorderPainter` 会读取这些样式信息，并根据不同的 `border-style` 调用相应的绘制逻辑（例如 `DrawDashedDottedBoxSideFromPath` 来绘制虚线和点线边框），同时考虑 `border-radius` 生成圆角路径，并处理 `opacity` 带来的透明度影响。

* **透明度处理:** 当 CSS 中边框颜色具有 alpha 值（例如 `rgba(255, 0, 0, 0.5)`）或者元素本身设置了 `opacity` 时，这段代码中的 `ComplexBorderInfo` 和 `PaintOpacityGroup` 函数会被调用。
    * **假设输入 (CSS):**
      ```css
      div {
        border: 5px solid rgba(0, 0, 255, 0.7); /* 半透明蓝色边框 */
      }
      ```
    * **功能体现:** `BuildOpacityGroups` 会创建一个透明度组，其中包含这个半透明的边框。`PaintOpacityGroup` 会创建相应的透明图层，并以正确的透明度绘制边框。

**逻辑推理的假设输入与输出:**

* **假设输入:**  一个矩形元素，上边框为红色实线 (不透明)，右边框为蓝色虚线 (50% 透明度)，下边框为绿色点线 (不透明)，左边框为黑色双线 (不透明)。
* **输出:**  `BuildOpacityGroups` 函数会创建一个包含一个透明度组的 `opacity_groups` 向量，该组包含右边框。其他边框将以不透明的方式直接绘制，或者可能在之前的代码部分中处理。绘制顺序会优先绘制透明度较低的边框，以便正确混合。

**涉及用户或者编程常见的使用错误举例说明:**

* **颜色透明度与元素透明度的混淆:** 用户可能只设置了元素的 `opacity` 属性，而没有显式设置边框颜色的 alpha 值，预期边框也会有相应的透明效果。但如果边框颜色是完全不透明的，即使元素是半透明的，边框仍然会以不透明的方式绘制。
    * **用户操作:** 在 CSS 中设置 `div { opacity: 0.5; border: 1px solid red; }`。
    * **调试线索:**  如果用户发现边框没有呈现预期的半透明效果，可以检查 `BoxBorderPainter` 中 `edge.GetColor().IsOpaque()` 的返回值，确认边框颜色是否真的是不透明的。

* **不正确的边框绘制顺序导致重叠问题:** 如果边框的透明度设置不当，可能会导致绘制顺序错误，使得透明的边框遮挡了不透明的边框。
    * **用户操作:** 设置两个相邻的边框，一个完全不透明，一个半透明，但预期半透明的边框应该在不透明边框之上。
    * **调试线索:** 可以通过查看 `ComplexBorderInfo` 中 `sorted_sides` 的排序结果来确认边框的绘制顺序是否符合预期。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在 HTML 中创建了一个元素，并使用 CSS 设置了复杂的边框样式:** 例如，设置了不同的边框颜色、样式、宽度，或者使用了 `border-radius` 创建了圆角。
2. **浏览器解析 HTML 和 CSS:**  渲染引擎开始构建渲染树，并将 CSS 样式应用到相应的元素上。
3. **布局计算:**  浏览器计算元素的几何属性，包括边框的尺寸和位置。
4. **绘制阶段:**  当需要绘制元素的边框时，会创建 `BoxBorderPainter` 对象，并将相关的样式信息传递给它。
5. **`ComputeBorderProperties` 函数被调用:**  分析边框的各种属性，例如是否统一颜色、样式、宽度，以及是否存在透明度。
6. **如果边框较为复杂 (例如存在透明度或非统一样式)，则会进入这部分代码:**  `BuildOpacityGroups` 会将具有相同透明度的边框边分组。
7. **`Paint` 函数被调用:**  根据边框的复杂程度，可能会调用 `PaintBorderFastPath` (如果满足快速路径条件) 或者进入更复杂的绘制流程。
8. **`PaintOpacityGroup` 函数被调用:**  对于具有透明度的边框，这个函数负责创建和管理透明图层，并按照排序后的顺序绘制边框边。
9. **`PaintSide` 函数被调用:**  最终绘制边框的每一条边，考虑边框样式、颜色、透明度以及圆角等因素。

**归纳一下它的功能:**

这部分代码的核心功能是**负责渲染 HTML 元素的复杂边框，特别是处理具有不同透明度的边框和圆角边框**。它通过对边框进行排序和分组，利用图层和路径等技术，确保边框能够按照 CSS 规范正确地绘制出来，并尝试优化绘制性能。

Prompt: 
```
这是目录为blink/renderer/core/paint/box_border_painter.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
inter.visible_edge_set_, side))
        sorted_sides.push_back(side);
    }
    DCHECK(!sorted_sides.empty());

    // Then sort them in paint order, based on three (prioritized) criteria:
    // alpha, style, side.
    std::sort(sorted_sides.begin(), sorted_sides.end(),
              [&border_painter](BoxSide a, BoxSide b) -> bool {
                const BorderEdge& edge_a = border_painter.Edge(a);
                const BorderEdge& edge_b = border_painter.Edge(b);

                const float alpha_a = edge_a.GetColor().Alpha();
                const float alpha_b = edge_b.GetColor().Alpha();
                if (alpha_a != alpha_b)
                  return alpha_a < alpha_b;

                const unsigned style_priority_a =
                    kStylePriority[static_cast<unsigned>(edge_a.BorderStyle())];
                const unsigned style_priority_b =
                    kStylePriority[static_cast<unsigned>(edge_b.BorderStyle())];
                if (style_priority_a != style_priority_b)
                  return style_priority_a < style_priority_b;

                return kSidePriority[static_cast<unsigned>(a)] <
                       kSidePriority[static_cast<unsigned>(b)];
              });

    // Finally, build the opacity group structures.
    BuildOpacityGroups(border_painter, sorted_sides);

    if (border_painter.is_rounded_)
      rounded_border_path.AddRoundedRect(border_painter.outer_);
  }

  Vector<OpacityGroup, 4> opacity_groups;

  // Potentially used when drawing rounded borders.
  Path rounded_border_path;

 private:
  void BuildOpacityGroups(const BoxBorderPainter& border_painter,
                          const Vector<BoxSide, 4>& sorted_sides) {
    float current_alpha = 0.0f;
    for (BoxSide side : sorted_sides) {
      const BorderEdge& edge = border_painter.Edge(side);
      const float edge_alpha = edge.GetColor().Alpha();

      DCHECK_GT(edge_alpha, 0.0f);
      DCHECK_GE(edge_alpha, current_alpha);
      // TODO(crbug.com/1434423): This float comparison looks very brittle. We
      // need to deduce the original intention of the code here. Also, this path
      // is clearly un-tested and caused some serious regressions when touched.
      // See crbug.com/1445288
      if (edge_alpha != current_alpha) {
        opacity_groups.push_back(OpacityGroup(edge_alpha));
        current_alpha = edge_alpha;
      }

      DCHECK(!opacity_groups.empty());
      OpacityGroup& current_group = opacity_groups.back();
      current_group.sides.push_back(side);
      current_group.edge_flags |= EdgeFlagForSide(side);
    }

    DCHECK(!opacity_groups.empty());
  }
};

void BoxBorderPainter::DrawDoubleBorder() const {
  DCHECK(is_uniform_color_);
  DCHECK(is_uniform_style_);
  DCHECK(FirstEdge().BorderStyle() == EBorderStyle::kDouble);
  DCHECK(visible_edge_set_ == kAllBorderEdges);

  const Color& color = FirstEdge().GetColor();

  // When painting outlines, we ignore outer/inner radii.
  const auto force_rectangular = !outer_.IsRounded() && !inner_.IsRounded();

  AutoDarkMode auto_dark_mode(PaintAutoDarkMode(style_, element_role_));

  // outer stripe
  const PhysicalBoxStrut outer_third_outsets =
      DoubleStripeOutsets(BorderEdge::kDoubleBorderStripeOuter);
  FloatRoundedRect outer_third_rect =
      RoundedBorderGeometry::PixelSnappedRoundedBorderWithOutsets(
          style_, border_rect_, outer_third_outsets, sides_to_include_);
  if (force_rectangular)
    outer_third_rect.SetRadii(FloatRoundedRect::Radii());
  DrawBleedAdjustedDRRect(context_, bleed_avoidance_, outer_, outer_third_rect,
                          color, auto_dark_mode);

  // inner stripe
  const PhysicalBoxStrut inner_third_outsets =
      DoubleStripeOutsets(BorderEdge::kDoubleBorderStripeInner);
  FloatRoundedRect inner_third_rect =
      RoundedBorderGeometry::PixelSnappedRoundedBorderWithOutsets(
          style_, border_rect_, inner_third_outsets, sides_to_include_);
  if (force_rectangular)
    inner_third_rect.SetRadii(FloatRoundedRect::Radii());
  context_.FillDRRect(inner_third_rect, inner_, color, auto_dark_mode);
}

bool BoxBorderPainter::PaintBorderFastPath() const {
  if (!is_uniform_color_ || !is_uniform_style_ || !inner_.IsRenderable())
    return false;

  if (FirstEdge().BorderStyle() != EBorderStyle::kSolid &&
      FirstEdge().BorderStyle() != EBorderStyle::kDouble)
    return false;

  if (visible_edge_set_ == kAllBorderEdges) {
    if (FirstEdge().BorderStyle() == EBorderStyle::kSolid) {
      if (is_uniform_width_ && !outer_.IsRounded()) {
        // 4-side, solid, uniform-width, rectangular border => one drawRect()
        DrawSolidBorderRect(context_, gfx::ToRoundedRect(outer_.Rect()),
                            FirstEdge().Width(), FirstEdge().GetColor(),
                            PaintAutoDarkMode(style_, element_role_));
      } else {
        // 4-side, solid border => one drawDRRect()
        DrawBleedAdjustedDRRect(context_, bleed_avoidance_, outer_, inner_,
                                FirstEdge().GetColor(),
                                PaintAutoDarkMode(style_, element_role_));
      }
    } else {
      // 4-side, double border => 2x drawDRRect()
      DCHECK(FirstEdge().BorderStyle() == EBorderStyle::kDouble);
      DrawDoubleBorder();
    }

    return true;
  }

  // This is faster than the normal complex border path only if it avoids
  // creating transparency layers (when the border is translucent).
  if (FirstEdge().BorderStyle() == EBorderStyle::kSolid &&
      !outer_.IsRounded() && has_transparency_) {
    DCHECK(visible_edge_set_ != kAllBorderEdges);
    // solid, rectangular border => one drawPath()
    Path path;
    path.SetWindRule(RULE_NONZERO);

    for (auto side :
         {BoxSide::kTop, BoxSide::kRight, BoxSide::kBottom, BoxSide::kLeft}) {
      const BorderEdge& curr_edge = Edge(side);
      if (curr_edge.ShouldRender()) {
        path.AddRect(gfx::RectF(CalculateSideRect(outer_, curr_edge, side)));
      }
    }

    context_.SetFillColor(FirstEdge().GetColor());
    context_.FillPath(path, PaintAutoDarkMode(style_, element_role_));
    return true;
  }

  return false;
}

BoxBorderPainter::BoxBorderPainter(GraphicsContext& context,
                                   const PhysicalRect& border_rect,
                                   const ComputedStyle& style,
                                   BackgroundBleedAvoidance bleed_avoidance,
                                   PhysicalBoxSides sides_to_include)
    : context_(context),
      border_rect_(border_rect),
      style_(style),
      bleed_avoidance_(bleed_avoidance),
      sides_to_include_(sides_to_include),
      visible_edge_count_(0),
      first_visible_edge_(0),
      visible_edge_set_(0),
      is_uniform_style_(true),
      is_uniform_width_(true),
      is_uniform_color_(true),
      is_rounded_(false),
      has_transparency_(false) {
  style.GetBorderEdgeInfo(edges_, sides_to_include);
  ComputeBorderProperties();

  // No need to compute the rrects if we don't have any borders to draw.
  if (!visible_edge_set_)
    return;

  outer_ = RoundedBorderGeometry::PixelSnappedRoundedBorder(style_, border_rect,
                                                            sides_to_include);
  inner_ = RoundedBorderGeometry::PixelSnappedRoundedInnerBorder(
      style_, border_rect, sides_to_include);

  // Make sure that the border width isn't larger than the border box, which
  // can pixel snap smaller.
  float max_width = outer_.Rect().width();
  float max_height = outer_.Rect().height();
  Edge(BoxSide::kTop).ClampWidth(max_height);
  Edge(BoxSide::kRight).ClampWidth(max_width);
  Edge(BoxSide::kBottom).ClampWidth(max_height);
  Edge(BoxSide::kLeft).ClampWidth(max_width);

  is_rounded_ = outer_.IsRounded();

  element_role_ = DarkModeFilter::ElementRole::kBorder;
}

BoxBorderPainter::BoxBorderPainter(GraphicsContext& context,
                                   const ComputedStyle& style,
                                   const PhysicalRect& border_rect,
                                   int width,
                                   const PhysicalBoxStrut& inner_outsets)
    : context_(context),
      border_rect_(border_rect),
      outer_outsets_(inner_outsets + PhysicalBoxStrut(LayoutUnit(width))),
      style_(style),
      bleed_avoidance_(kBackgroundBleedNone),
      sides_to_include_(PhysicalBoxSides()),
      visible_edge_count_(0),
      first_visible_edge_(0),
      visible_edge_set_(0),
      is_uniform_style_(true),
      is_uniform_width_(true),
      is_uniform_color_(true),
      is_rounded_(false),
      has_transparency_(false) {
  DCHECK(style.HasOutline());

  BorderEdge edge(width,
                  style.VisitedDependentColor(GetCSSPropertyOutlineColor()),
                  style.OutlineStyle());
  for (auto& e : edges_)
    e = edge;
  ComputeBorderProperties();

  outer_ = RoundedBorderGeometry::PixelSnappedRoundedBorderWithOutsets(
      style, border_rect, outer_outsets_);
  is_rounded_ = outer_.IsRounded();

  inner_ = RoundedBorderGeometry::PixelSnappedRoundedBorderWithOutsets(
      style, border_rect, inner_outsets);

  element_role_ = DarkModeFilter::ElementRole::kBackground;
}

void BoxBorderPainter::ComputeBorderProperties() {
  for (unsigned i = 0; i < std::size(edges_); ++i) {
    const BorderEdge& edge = edges_[i];

    if (!edge.ShouldRender()) {
      if (edge.PresentButInvisible()) {
        is_uniform_width_ = false;
        is_uniform_color_ = false;
      }

      continue;
    }

    DCHECK(!edge.GetColor().IsFullyTransparent());

    visible_edge_count_++;
    visible_edge_set_ |= EdgeFlagForSide(static_cast<BoxSide>(i));

    if (!edge.GetColor().IsOpaque()) {
      has_transparency_ = true;
    }

    if (visible_edge_count_ == 1) {
      first_visible_edge_ = i;
      continue;
    }

    is_uniform_style_ &=
        edge.BorderStyle() == edges_[first_visible_edge_].BorderStyle();
    is_uniform_width_ &= edge.Width() == edges_[first_visible_edge_].Width();
    is_uniform_color_ &= edge.SharesColorWith(edges_[first_visible_edge_]);
  }
}

void BoxBorderPainter::Paint() const {
  if (!visible_edge_count_ || outer_.Rect().IsEmpty())
    return;

  if (PaintBorderFastPath())
    return;

  bool clip_to_outer_border = outer_.IsRounded();
  GraphicsContextStateSaver state_saver(context_, clip_to_outer_border);
  if (clip_to_outer_border) {
    // For BackgroundBleedClip{Only,Layer}, the outer rrect clip is already
    // applied.
    if (!BleedAvoidanceIsClipping(bleed_avoidance_))
      context_.ClipRoundedRect(outer_);

    if (inner_.IsRenderable() && !inner_.IsEmpty())
      context_.ClipOutRoundedRect(inner_);
  }

  const ComplexBorderInfo border_info(*this);
  PaintOpacityGroup(border_info, 0, 1);
}

// In order to maximize the use of overdraw as a corner seam avoidance
// technique, we draw translucent border sides using the following algorithm:
//
//   1) cluster sides sharing the same opacity into "opacity groups"
//      [ComplexBorderInfo]
//   2) sort groups in increasing opacity order [ComplexBorderInfo]
//   3) reverse-iterate over groups (decreasing opacity order), pushing nested
//      transparency layers with adjusted/relative opacity [paintOpacityGroup]
//   4) iterate over groups (increasing opacity order), painting actual group
//      contents and then ending their corresponding transparency layer
//      [PaintOpacityGroup]
//
// Layers are created in decreasing opacity order (top -> bottom), while actual
// border sides are drawn in increasing opacity order (bottom -> top). At each
// level, opacity is adjusted to account for accumulated/ancestor layer alpha.
// Because opacity is applied via layers, the actual draw paint is opaque.
//
// As an example, let's consider a border with the following sides/opacities:
//
//   top:    1.0
//   right:  0.25
//   bottom: 0.5
//   left:   0.25
//
// These are grouped and sorted in ComplexBorderInfo as follows:
//
//   group[0]: { alpha: 1.0,  sides: top }
//   group[1]: { alpha: 0.5,  sides: bottom }
//   group[2]: { alpha: 0.25, sides: right, left }
//
// Applying the algorithm yields the following paint sequence:
//
//                                // no layer needed for group 0 (alpha = 1)
//   beginLayer(0.5)              // layer for group 1
//     beginLayer(0.5)            // layer for group 2 (alpha: 0.5 * 0.5 = 0.25)
//       paintSides(right, left)  // paint group 2
//     endLayer
//     paintSides(bottom)         // paint group 1
//   endLayer
//   paintSides(top)              // paint group 0
//
// Note that we're always drawing using opaque paints on top of less-opaque
// content - hence we can use overdraw to mask portions of the previous sides.
//
BorderEdgeFlags BoxBorderPainter::PaintOpacityGroup(
    const ComplexBorderInfo& border_info,
    unsigned index,
    float effective_opacity) const {
  DCHECK(effective_opacity > 0 && effective_opacity <= 1);

  const wtf_size_t opacity_group_count = border_info.opacity_groups.size();

  // For overdraw logic purposes, treat missing/transparent edges as completed.
  if (index >= opacity_group_count)
    return ~visible_edge_set_;

  // Groups are sorted in increasing opacity order, but we need to create layers
  // in decreasing opacity order - hence the reverse iteration.
  const OpacityGroup& group =
      border_info.opacity_groups[opacity_group_count - index - 1];

  // Adjust this group's paint opacity to account for ancestor transparency
  // layers (needed in case we avoid creating a layer below).
  float paint_alpha = group.alpha / effective_opacity;
  DCHECK_LE(paint_alpha, 1.0f);

  // For the last (bottom) group, we can skip the layer even in the presence of
  // opacity iff it contains no adjecent edges (no in-group overdraw
  // possibility).
  bool needs_layer =
      group.alpha != 1.0f && (IncludesAdjacentEdges(group.edge_flags) ||
                              (index + 1 < border_info.opacity_groups.size()));

  if (needs_layer) {
    DCHECK_LT(group.alpha, effective_opacity);

    context_.BeginLayer(group.alpha / effective_opacity);
    effective_opacity = group.alpha;

    // Group opacity is applied via a layer => we draw the members using opaque
    // paint.
    paint_alpha = 1.0f;
  }

  // Recursion may seem unpalatable here, but
  //   a) it has an upper bound of 4
  //   b) only triggers at all when mixing border sides with different opacities
  //   c) it allows us to express the layer nesting algorithm more naturally
  BorderEdgeFlags completed_edges =
      PaintOpacityGroup(border_info, index + 1, effective_opacity);

  // Paint the actual group edges with an alpha adjusted to account for
  // ancenstor layers opacity.
  for (BoxSide side : group.sides) {
    PaintSide(border_info, side, paint_alpha, completed_edges);
    completed_edges |= EdgeFlagForSide(side);
  }

  if (needs_layer)
    context_.EndLayer();

  return completed_edges;
}

void BoxBorderPainter::PaintSide(const ComplexBorderInfo& border_info,
                                 BoxSide side,
                                 float alpha,
                                 BorderEdgeFlags completed_edges) const {
  const BorderEdge& edge = Edge(side);
  DCHECK(edge.ShouldRender());
  const Color color = Color::FromColorSpace(
      edge.GetColor().GetColorSpace(), edge.GetColor().Param0(),
      edge.GetColor().Param1(), edge.GetColor().Param2(), alpha);

  gfx::Rect side_rect = gfx::ToRoundedRect(outer_.Rect());
  const Path* path = nullptr;

  // TODO(fmalita): find a way to consolidate these without sacrificing
  // readability.
  switch (side) {
    case BoxSide::kTop: {
      bool use_path =
          is_rounded_ && (BorderStyleHasInnerDetail(edge.BorderStyle()) ||
                          BorderWillArcInnerEdge(inner_.GetRadii().TopLeft(),
                                                 inner_.GetRadii().TopRight()));
      if (use_path) {
        path = &border_info.rounded_border_path;
      } else {
        side_rect.set_height(edge.Width());
      }

      PaintOneBorderSide(side_rect, BoxSide::kTop, BoxSide::kLeft,
                         BoxSide::kRight, path, color, completed_edges);
      break;
    }
    case BoxSide::kBottom: {
      bool use_path = is_rounded_ &&
                      (BorderStyleHasInnerDetail(edge.BorderStyle()) ||
                       BorderWillArcInnerEdge(inner_.GetRadii().BottomLeft(),
                                              inner_.GetRadii().BottomRight()));
      if (use_path) {
        path = &border_info.rounded_border_path;
      } else {
        SetToBottomSideRect(side_rect, edge.Width());
      }

      PaintOneBorderSide(side_rect, BoxSide::kBottom, BoxSide::kLeft,
                         BoxSide::kRight, path, color, completed_edges);
      break;
    }
    case BoxSide::kLeft: {
      bool use_path =
          is_rounded_ && (BorderStyleHasInnerDetail(edge.BorderStyle()) ||
                          BorderWillArcInnerEdge(inner_.GetRadii().BottomLeft(),
                                                 inner_.GetRadii().TopLeft()));
      if (use_path) {
        path = &border_info.rounded_border_path;
      } else {
        side_rect.set_width(edge.Width());
      }

      PaintOneBorderSide(side_rect, BoxSide::kLeft, BoxSide::kTop,
                         BoxSide::kBottom, path, color, completed_edges);
      break;
    }
    case BoxSide::kRight: {
      bool use_path = is_rounded_ &&
                      (BorderStyleHasInnerDetail(edge.BorderStyle()) ||
                       BorderWillArcInnerEdge(inner_.GetRadii().BottomRight(),
                                              inner_.GetRadii().TopRight()));
      if (use_path) {
        path = &border_info.rounded_border_path;
      } else {
        SetToRightSideRect(side_rect, edge.Width());
      }

      PaintOneBorderSide(side_rect, BoxSide::kRight, BoxSide::kTop,
                         BoxSide::kBottom, path, color, completed_edges);
      break;
    }
    default:
      NOTREACHED();
  }
}

BoxBorderPainter::MiterType BoxBorderPainter::ComputeMiter(
    BoxSide side,
    BoxSide adjacent_side,
    BorderEdgeFlags completed_edges) const {
  const BorderEdge& adjacent_edge = Edge(adjacent_side);

  // No miters for missing edges.
  if (!adjacent_edge.UsedWidth()) {
    return kNoMiter;
  }

  // The adjacent edge will overdraw this corner, resulting in a correct miter.
  if (WillOverdraw(adjacent_side, adjacent_edge.BorderStyle(), completed_edges))
    return kNoMiter;

  // Color transitions require miters. Use miters compatible with the AA drawing
  // mode to avoid introducing extra clips.
  if (!ColorsMatchAtCorner(side, adjacent_side))
    return kSoftMiter;

  // Non-anti-aliased miters ensure correct same-color seaming when required by
  // style.
  if (BorderStylesRequireMiter(side, adjacent_side, Edge(side).BorderStyle(),
                               adjacent_edge.BorderStyle()))
    return kHardMiter;

  // Overdraw the adjacent edge when the colors match and we have no style
  // restrictions.
  return kNoMiter;
}

bool BoxBorderPainter::MitersRequireClipping(MiterType miter1,
                                             MiterType miter2,
                                             EBorderStyle style) {
  // Clipping is required if any of the present miters doesn't match the current
  // AA mode.
  bool should_clip = miter1 == kHardMiter || miter2 == kHardMiter;

  // Some styles require clipping for any type of miter.
  should_clip = should_clip || ((miter1 != kNoMiter || miter2 != kNoMiter) &&
                                StyleRequiresClipPolygon(style));

  return should_clip;
}

void BoxBorderPainter::PaintOneBorderSide(
    const gfx::Rect& side_rect,
    BoxSide side,
    BoxSide adjacent_side1,
    BoxSide adjacent_side2,
    const Path* path,
    Color color,
    BorderEdgeFlags completed_edges) const {
  const BorderEdge& edge_to_render = Edge(side);
  DCHECK(edge_to_render.Width());
  const BorderEdge& adjacent_edge1 = Edge(adjacent_side1);
  const BorderEdge& adjacent_edge2 = Edge(adjacent_side2);

  if (path) {
    MiterType miter1 =
        ColorsMatchAtCorner(side, adjacent_side1) ? kHardMiter : kSoftMiter;
    MiterType miter2 =
        ColorsMatchAtCorner(side, adjacent_side2) ? kHardMiter : kSoftMiter;

    GraphicsContextStateSaver state_saver(context_);

    ClipBorderSidePolygon(side, miter1, miter2);
    if (!inner_.IsRenderable()) {
      FloatRoundedRect adjusted_inner_rect =
          CalculateAdjustedInnerBorder(inner_, side);
      if (!adjusted_inner_rect.IsEmpty()) {
        context_.ClipOutRoundedRect(adjusted_inner_rect);
      }
    }

    int stroke_thickness =
        std::max(std::max(edge_to_render.Width(), adjacent_edge1.Width()),
                 adjacent_edge2.Width());
    DrawBoxSideFromPath(*path, edge_to_render.Width(), stroke_thickness, side,
                        color, edge_to_render.BorderStyle());
  } else {
    MiterType miter1 = ComputeMiter(side, adjacent_side1, completed_edges);
    MiterType miter2 = ComputeMiter(side, adjacent_side2, completed_edges);
    bool should_clip =
        MitersRequireClipping(miter1, miter2, edge_to_render.BorderStyle());

    GraphicsContextStateSaver clip_state_saver(context_, should_clip);
    if (should_clip) {
      ClipBorderSidePolygon(side, miter1, miter2);
      // Miters are applied via clipping, no need to draw them.
      miter1 = miter2 = kNoMiter;
    }

    DrawLineForBoxSide(
        context_, side_rect.x(), side_rect.y(), side_rect.right(),
        side_rect.bottom(), side, color, edge_to_render.BorderStyle(),
        miter1 != kNoMiter ? adjacent_edge1.Width() : 0,
        miter2 != kNoMiter ? adjacent_edge2.Width() : 0,
        /*antialias*/ true, PaintAutoDarkMode(style_, element_role_));
  }
}

void BoxBorderPainter::DrawBoxSideFromPath(const Path& border_path,
                                           int border_thickness,
                                           int stroke_thickness,
                                           BoxSide side,
                                           Color color,
                                           EBorderStyle border_style) const {
  if (border_thickness <= 0)
    return;

  // The caller should have adjusted border_style.
  DCHECK_EQ(border_style,
            BorderEdge::EffectiveStyle(border_style, border_thickness));

  switch (border_style) {
    case EBorderStyle::kNone:
    case EBorderStyle::kHidden:
      return;
    case EBorderStyle::kDotted:
    case EBorderStyle::kDashed: {
      DrawDashedDottedBoxSideFromPath(border_thickness, stroke_thickness, color,
                                      border_style);
      return;
    }
    case EBorderStyle::kDouble: {
      DrawDoubleBoxSideFromPath(border_path, border_thickness, stroke_thickness,
                                side, color);
      return;
    }
    case EBorderStyle::kRidge:
    case EBorderStyle::kGroove: {
      DrawRidgeGrooveBoxSideFromPath(border_path, border_thickness,
                                     stroke_thickness, side, color,
                                     border_style);
      return;
    }
    case EBorderStyle::kInset:
    case EBorderStyle::kOutset:
      color = CalculateBorderStyleColor(border_style, side, color);
      break;
    default:
      break;
  }

  context_.SetFillColor(color);
  context_.FillRect(gfx::ToRoundedRect(outer_.Rect()),
                    PaintAutoDarkMode(style_, element_role_));
}

void BoxBorderPainter::DrawDashedDottedBoxSideFromPath(
    int border_thickness,
    int stroke_thickness,
    Color color,
    EBorderStyle border_style) const {
  // Convert the path to be down the middle of the dots or dashes.
  Path centerline_path;
  centerline_path.AddRoundedRect(
      RoundedBorderGeometry::PixelSnappedRoundedBorderWithOutsets(
          style_, border_rect_, CenterOutsets(), sides_to_include_));

  context_.SetStrokeColor(color);

  const StrokeStyle stroke_style =
      border_style == EBorderStyle::kDashed ? kDashedStroke : kDottedStroke;
  if (!StyledStrokeData::StrokeIsDashed(border_thickness, stroke_style)) {
    DrawWideDottedBoxSideFromPath(centerline_path, border_thickness);
    return;
  }

  // The stroke is doubled here because the provided path is the
  // outside edge of the border so half the stroke is clipped off, with
  // the extra multiplier so that the clipping mask can antialias
  // the edges to prevent jaggies.
  const float thickness_multiplier = 2 * 1.1f;
  StyledStrokeData styled_stroke;
  styled_stroke.SetThickness(stroke_thickness * thickness_multiplier);
  styled_stroke.SetStyle(stroke_style);

  // TODO(crbug.com/344234): stroking the border path causes issues with
  // tight corners.
  const StrokeData stroke_data = styled_stroke.ConvertToStrokeData(
      {static_cast<int>(centerline_path.length()), border_thickness,
       centerline_path.IsClosed()});
  context_.SetStroke(stroke_data);
  context_.StrokePath(centerline_path,
                      PaintAutoDarkMode(style_, element_role_));
}

void BoxBorderPainter::DrawWideDottedBoxSideFromPath(
    const Path& border_path,
    int border_thickness) const {
  StyledStrokeData styled_stroke;
  styled_stroke.SetThickness(border_thickness);
  styled_stroke.SetStyle(kDottedStroke);

  // TODO(crbug.com/344234): stroking the border path causes issues with
  // tight corners.
  const StrokeData stroke_data = styled_stroke.ConvertToStrokeData(
      {static_cast<int>(border_path.length()), border_thickness,
       border_path.IsClosed()});
  context_.SetStroke(stroke_data);
  context_.StrokePath(border_path, PaintAutoDarkMode(style_, element_role_));
}

void BoxBorderPainter::DrawDoubleBoxSideFromPath(const Path& border_path,
                                                 int border_thickness,
                                                 int stroke_thickness,
                                                 BoxSide side,
                                                 Color color) const {
  // Draw inner border line
  {
    GraphicsContextStateSaver state_saver(context_);
    const PhysicalBoxStrut inner_outsets =
        DoubleStripeOutsets(BorderEdge::kDoubleBorderStripeInner);
    FloatRoundedRect inner_clip =
        RoundedBorderGeometry::PixelSnappedRoundedBorderWithOutsets(
            style_, border_rect_, inner_outsets, sides_to_include_);

    context_.ClipRoundedRect(inner_clip);
    DrawBoxSideFromPath(border_path, border_thickness, stroke_thickness, side,
                        color, EBorderStyle::kSolid);
  }

  // Draw outer border line
  {
    GraphicsContextStateSaver state_saver(context_);
    PhysicalRect used_border_rect = border_rect_;
    PhysicalBoxStrut outer_outsets =
        DoubleStripeOutsets(BorderEdge::kDoubleBorderStripeOuter);

    if (BleedAvoidanceIsClipping(bleed_avoidance_)) {
      used_border_rect.Inflate(LayoutUnit(1));
      outer_outsets.Inflate(LayoutUnit(-1));
    }

    FloatRoundedRect outer_clip =
        RoundedBorderGeometry::PixelSnappedRoundedBorderWithOutsets(
            style_, used_border_rect, outer_outsets, sides_to_include_);
    context_.ClipOutRoundedRect(outer_clip);
    DrawBoxSideFromPath(border_path, border_thickness, stroke_thickness, side,
                        color, EBorderStyle::kSolid);
  }
}

void BoxBorderPainter::DrawRidgeGrooveBoxSideFromPath(
    const Path& border_path,
    int border_thickness,
    int stroke_thickness,
    BoxSide side,
    Color color,
    EBorderStyle border_style) const {
  EBorderStyle s1;
  EBorderStyle s2;
  if (border_style == EBorderStyle::kGroove) {
    s1 = EBorderStyle::kInset;
    s2 = EBorderStyle::kOutset;
  } else {
    s1 = EBorderStyle::kOutset;
    s2 = EBorderStyle::kInset;
  }

  // Paint full border
  DrawBoxSideFromPath(border_path, border_thickness, stroke_thickness, side,
                      color, s1);

  // Paint inner only
  GraphicsContextStateSaver state_saver(context_);
  FloatRoundedRect clip_rect =
      RoundedBorderGeometry::PixelSnappedRoundedBorderWithOutsets(
          style_, border_rect_, CenterOutsets(), sides_to_include_);

  context_.ClipRoundedRect(clip_rect);
  DrawBoxSideFromPath(border_path, border_thickness, stroke_thickness, side,
                      color, s2);
}

gfx::Rect BoxBorderPainter::CalculateSideRectIncludingInner(
    BoxSide side) const {
  gfx::Rect side_rect = gfx::ToRoundedRect(outer_.Rect());
  int width;

  switch (side) {
    case BoxSide::kTop:
      width = side_rect.height() - Edge(BoxSide::kBottom).Width();
      side_rect.set_height(width);
      break;
    case BoxSide::kBottom:
      width = side_rect.height() - Edge(BoxSide::kTop).Width();
      SetToBottomSideRect(side_rect, width);
      break;
    case BoxSide::kLeft:
      width = side_rect.width() - Edge(BoxSide::kRight).Width();
      side_rect.set_width(width);
      break;
    case BoxSide::kRight:
      width = side_rect.width() - Edge(BoxSide::kLeft).Width();
      SetToRightSideRect(side_rect, width);
      break;
  }

  return side_rect;
}

void BoxBorderPainter::ClipBorderSidePolygon(BoxSide side,
                                             MiterType first_miter,
                                             MiterType second_miter) const {
  DCHECK(first_miter != kNoMiter || second_miter != kNoMiter);

  // The boundary of the edge for fill.
  gfx::PointF edge_quad[4];
  Vector<gfx::PointF, 5> edge_pentagon;

  // Point 1 of the rectilinear bounding box of edge_quad.
  gfx::PointF bound_quad1;
  // Point 2 of the rectilinear bounding box of edge_quad.
  gfx::PointF bound_quad2;

  // For each side, create a quad that encompasses all parts of that side that
  // may draw, including areas inside the innerBorder.
  //
  //         0----------------3
  //       3  \              /  0
  //       |\  1----------- 2  /|
  //       | 2                1 |
  //       | |                | |
  //       | |                | |
  //       | 1                2 |
  //       |/  2------------1  \|
  //       0  /              \  3
  //         3----------------0

  // Points 1 and 2 of each quad are initially the corresponding corners of the
  // inner rect. If an inner corner is rounded, the corresponding point will be
  // moved inside to ensure the quad contains the half corner.
  // However, if the inner border is not renderable, and line 1-2 would clip the
  // rounded corner near the miter, we need to insert a point between 1 and 2 to
  // create a pentagon.
  // 0-------------3       0-------------3       0-------------4
  // |\           /|       |\           /|       |\           /|
  // | 1---------2 |       | \---------2 |       | \---------3 |
  // | |         | |       | |\       /| |       | |\        | |
  // | |         | |       | | \     / | |       | | \       | |
  // | |         | |  -->  | |  \   /  | |  -->  | |  \      | |
  // | |         | |       | |    1    | |       | |    1----2 |
  // | |         | |       | |         | |       | |         | |
  // | /---------\ |       | /---------\ |       | /---------\ |
  //  -------------         -------------         -------------

  const gfx::PointF inner_points[4] = {
      inner_.Rect().origin(),
      inner_.Rect().top_right(),
      inner_.Rect().bottom_right(),
      inner_.Rect().bottom_left(),
  };
  const gfx::PointF outer_points[4] = {
      outer_.Rect().origin(),
      outer_.Rect().top_right(),
      outer_.Rect().bottom_right(),
      outer_.Rect().bottom_left(),
  };

  // Offset size and direction to expand clipping quad
  const static float kExtensionLength = 1e-1f;
  gfx::Vector2dF extension_offset;
  switch (side) {
    case BoxSide::kTop:
      edge_quad[0] = outer_points[0];
      edge_quad[1] = inner_points[0];
      edge_quad[2] = inner_points[1];
      edge_quad[3] = outer_points[1];

      DCHECK(edge_quad[0].y() == edge_quad[3].y());
      DCHECK(edge_quad[1].y() == edge_quad[2].y());

      bound_quad1 = gfx::PointF(edge_quad[0].x(), edge_quad[1].y());
      bound_quad2 = gfx::PointF(edge_quad[3].x(), edge_quad[2].y());

      extension_offset.set_x(-kExtensionLength);
      extension_offset.set_y(0);

      if (!inner_.GetRadii().TopLeft().IsZero()) {
        FindIntersection(
            edge_quad[0], edge_quad[1],
            gfx::PointF(edge_quad[1].x() + inner_.GetRadii().TopLeft().width(),
                        edge_quad[1].y()),
            gfx::PointF(
                edge_quad[1].x(),
                edge_quad[1].y() + inner_.GetRadii().TopLeft().height()),
            edge_quad[1]);
        DCHECK(bound_quad1.y() <= edge_quad[1].y());
        bound_quad1.set_y(edge_quad[1].y());
        bound_quad2.set_y(edge_quad[1].y());

        i
"""


```