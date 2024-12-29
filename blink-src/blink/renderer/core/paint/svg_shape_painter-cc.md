Response:
Let's break down the thought process for analyzing this C++ source file.

1. **Understand the Core Task:** The request is to analyze `svg_shape_painter.cc`. The name itself is highly indicative: it's responsible for *painting* SVG *shapes*. This immediately gives us a central theme.

2. **Identify Key Classes and Concepts:**  The `#include` directives at the top are crucial. They reveal the dependencies and the vocabulary of the code. We see:
    * `LayoutSVGShape`: This is clearly the object being painted. "Layout" suggests it's related to the rendering tree.
    * `PaintInfo`:  A common structure in Blink's rendering pipeline, likely containing information about the current paint operation (context, clip rect, etc.).
    * `GraphicsContext`: The interface for drawing primitives (rectangles, paths, etc.).
    * `cc::PaintFlags`: Flags that control the appearance of painted objects (color, anti-aliasing, etc.).
    * `AffineTransform`: Used for transformations (translations, rotations, scaling).
    * `SVGModelObjectPainter`, `SVGContainerPainter`, `SVGObjectPainter`:  These suggest a hierarchy of painters for different SVG elements.
    * `ScopedSVGPaintState`, `ScopedSVGTransformState`: RAII wrappers for managing paint and transform states, ensuring they're restored.
    * `PaintOrderArray`: Deals with the order in which fill, stroke, and markers are painted.
    * `LayoutSVGResourceMarker`:  Related to SVG markers (small graphics attached to the vertices of a shape).

3. **Trace the Main Functionality:** The `Paint()` method seems like the entry point. It checks for visibility, culling, sets up transformations, and then calls `PaintShape()`. This establishes the high-level flow.

4. **Analyze `PaintShape()`:** This function handles the actual drawing. It considers:
    * `paint-order`:  The order of fill, stroke, and markers.
    * Fill: If a fill is present, it creates `PaintFlags` and calls `FillShape()`.
    * Stroke: If a stroke is present, it handles "non-scaling-stroke" logic, creates `PaintFlags`, applies stroke styles, and calls `StrokeShape()`.
    * Markers: Calls `PaintMarkers()`.

5. **Examine `FillShape()` and `StrokeShape()`:** These functions are responsible for drawing the basic shapes (rectangles, circles, ellipses, paths) using the `GraphicsContext`. They also handle dark mode adjustments.

6. **Delve into `PaintMarkers()` and `PaintMarker()`:**  These methods deal with drawing the markers at specified positions along the shape's path. They retrieve marker definitions and apply transformations.

7. **Connect to Web Technologies (HTML, CSS, JavaScript):**  Now, consider how these C++ concepts relate to the front-end:
    * **HTML:** The `<svg>` tag and its shape elements (`<rect>`, `<circle>`, `<path>`, etc.) are the starting point. The attributes of these elements (e.g., `fill`, `stroke`, `stroke-width`, `marker-start`) directly influence the painting process.
    * **CSS:**  CSS properties like `fill`, `stroke`, `stroke-width`, `fill-rule`, `stroke-dasharray`, `visibility`, `opacity`, `transform`, and `paint-order` are critical. The `ComputedStyle` object in the code holds the resolved CSS values. The `shape-rendering` property influences anti-aliasing.
    * **JavaScript:** JavaScript can manipulate the DOM (including SVG elements and their attributes), and CSS styles. This can trigger repaints and thus invoke this code. Animations using CSS transitions/animations or JavaScript-based animations also lead to repeated calls to the paint functions.

8. **Identify Logic and Assumptions:**
    * **Culling:** The code checks if the shape is within the cull rect to avoid unnecessary drawing. This optimizes performance.
    * **Non-scaling stroke:**  This SVG feature requires special handling to ensure the stroke width remains constant regardless of transformations.
    * **Paint order:** The `paint-order` property in CSS allows developers to control the stacking of fill, stroke, and markers.
    * **Markers:** The code correctly handles different marker types (start, mid, end).

9. **Consider User and Programming Errors:**
    * **Invalid SVG syntax:** While this code doesn't *parse* SVG, incorrect SVG attributes can lead to unexpected rendering (e.g., invalid `fill` or `stroke` values).
    * **Incorrect CSS:**  Using incorrect CSS properties or values will affect the painting.
    * **Performance issues:**  Complex SVG shapes or excessive use of filters/gradients can lead to slow rendering.
    * **Infinite loops (unlikely here):**  Although not directly evident in this snippet, complex interactions could theoretically lead to infinite repaint loops in a broader context.

10. **Think About Debugging:** How would a developer end up in this code?
    * **Visual inspection:**  Noticing rendering issues with SVG shapes.
    * **Performance profiling:** Identifying `SVGShapePainter::Paint` as a performance bottleneck.
    * **Breakpoints:** Setting breakpoints in `Paint()`, `PaintShape()`, etc., to inspect the painting process.
    * **Tracing/Logging:**  Adding logging statements to understand the flow of execution and the values of relevant variables.

11. **Structure the Answer:** Organize the findings into clear categories (functionality, relationships to web technologies, logic, errors, debugging). Provide specific examples to illustrate the points.

12. **Refine and Review:** Read through the analysis to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas that need further explanation. For instance, explicitly mentioning the interaction with the rendering pipeline (Layout Tree -> Paint Tree -> Display List) could add more context.

This structured approach, moving from the specific code to the broader context of web technologies and potential issues, allows for a comprehensive analysis of the given source file.
好的，让我们来分析一下 `blink/renderer/core/paint/svg_shape_painter.cc` 这个文件。

**文件功能概述:**

`SVGShapePainter` 类的主要职责是负责绘制 SVG 形状元素，例如 `<rect>`, `<circle>`, `<path>`, `<ellipse>` 等。它接收来自布局阶段的 `LayoutSVGShape` 对象，并利用 `GraphicsContext` 将这些形状渲染到屏幕上。

更具体地说，这个类处理以下任务：

1. **确定是否需要绘制:** 检查形状的可见性、是否为空以及是否被裁剪。
2. **应用变换:**  处理应用于形状的 SVG 变换（例如，平移、旋转、缩放）。
3. **管理绘制状态:** 使用 `ScopedSVGPaintState` 来设置和恢复绘制属性，如填充、描边颜色、透明度等。
4. **记录绘制操作:** 利用 `DrawingRecorder` 或 `PaintRecordBuilder` 来记录绘制操作，以便进行缓存和重放，提高性能。
5. **绘制填充:** 如果形状有填充，则使用 `FillShape` 方法进行绘制，考虑填充规则（例如，奇偶规则、非零环绕规则）。
6. **绘制描边:** 如果形状有描边，则使用 `StrokeShape` 方法进行绘制，考虑描边宽度、线型、线帽、线连接等属性。同时处理 `non-scaling-stroke` 属性，确保描边宽度在变换后保持不变。
7. **绘制标记 (Markers):** 如果形状定义了标记（如箭头或点），则使用 `PaintMarkers` 方法在路径的特定位置绘制这些标记。
8. **处理暗黑模式:**  使用 `PaintAutoDarkMode` 来根据页面的暗黑模式设置调整颜色。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`SVGShapePainter` 的功能直接受 HTML 中的 SVG 元素及其属性，以及 CSS 样式的影响。JavaScript 可以通过修改 DOM 或 CSS 来间接地影响这个类的行为。

* **HTML:**
    * **`<rect>`:**  当 HTML 中有 `<rect>` 元素时，会创建对应的 `LayoutSVGShape` 对象，`SVGShapePainter` 会根据其 `x`, `y`, `width`, `height` 属性绘制矩形。
    * **`<circle>`:**  类似地，`<circle>` 元素的 `cx`, `cy`, `r` 属性会影响 `SVGShapePainter` 如何绘制圆形。
    * **`<path>`:**  `<path>` 元素的 `d` 属性定义了复杂的路径，`SVGShapePainter` 会解析这个路径数据并绘制出来。
    * **`fill` 和 `stroke` 属性:**  这些属性定义了形状的填充颜色和描边颜色，`SVGShapePainter` 会读取这些值并应用到绘制中。
    * **`transform` 属性:**  SVG 的 `transform` 属性（例如 `translate`, `rotate`, `scale`）会影响 `SVGShapePainter` 应用的变换。
    * **`marker-start`, `marker-mid`, `marker-end` 属性:** 这些属性指定了在路径的起点、中间点和终点绘制的标记，`SVGShapePainter` 中的 `PaintMarkers` 方法会处理这些标记。

    **例子:**

    ```html
    <svg width="100" height="100">
      <rect x="10" y="10" width="80" height="80" fill="red" stroke="blue" stroke-width="3" />
    </svg>
    ```

    在这个例子中，`SVGShapePainter` 会接收到一个表示矩形的 `LayoutSVGShape` 对象。它会读取 `fill="red"` 和 `stroke="blue"`，并使用红色填充矩形，蓝色描边，描边宽度为 3px。

* **CSS:**
    * **`fill` 和 `stroke` 属性:**  CSS 也可以设置 SVG 元素的填充和描边颜色，优先级高于 HTML 属性。
    * **`fill-opacity` 和 `stroke-opacity`:**  控制填充和描边的透明度。
    * **`stroke-width`:**  设置描边的宽度。
    * **`stroke-dasharray`:**  定义虚线描边的模式。
    * **`visibility`:**  控制元素的可见性，如果 `visibility` 为 `hidden`，`SVGShapePainter` 会跳过绘制。
    * **`opacity`:**  设置元素的整体透明度。
    * **`transform`:**  CSS 的 `transform` 属性也会影响 SVG 元素的变换。
    * **`paint-order`:**  控制填充、描边和标记的绘制顺序。
    * **`shape-rendering`:**  影响形状渲染的质量和速度，例如 `crispEdges` 会禁用抗锯齿。
    * **`fill-rule`:**  定义如何判断一个点是否在路径的填充区域内。

    **例子:**

    ```css
    rect {
      fill: green;
      stroke: black;
      stroke-width: 5px;
      opacity: 0.7;
    }
    ```

    这段 CSS 会覆盖 HTML 中矩形的填充和描边颜色，并将不透明度设置为 0.7。`SVGShapePainter` 在绘制时会考虑这些 CSS 样式。

* **JavaScript:**
    * JavaScript 可以使用 DOM API 来修改 SVG 元素的属性和 CSS 样式。
    * 例如，JavaScript 可以改变 `<rect>` 的 `fill` 属性或使用 `element.style.fill = 'purple'` 来动态改变填充颜色，这将导致浏览器重新绘制，`SVGShapePainter` 会使用新的属性值进行绘制。
    * JavaScript 还可以通过创建和操作 SVG 元素来触发 `SVGShapePainter` 的执行。
    * JavaScript 动画库 (例如 GreenSock, Anime.js) 可以修改 SVG 元素的变换属性，导致 `SVGShapePainter` 在每一帧都进行重新绘制。

    **例子:**

    ```javascript
    const rectElement = document.querySelector('rect');
    rectElement.setAttribute('fill', 'orange'); // 修改填充颜色
    rectElement.style.transform = 'rotate(45deg)'; // 添加旋转变换
    ```

    这段 JavaScript 代码会动态修改矩形的填充颜色和添加旋转变换，`SVGShapePainter` 会在下一次绘制时使用这些新的属性值。

**逻辑推理的假设输入与输出:**

假设输入一个 `<path>` 元素，其 `d` 属性定义了一个简单的三角形，并设置了填充和描边：

**假设输入 (LayoutSVGShape 对象携带的信息):**

* **Geometry Type:** `kPath`
* **Path Data:**  定义一个三角形的 SkPath 对象，例如从 (10, 10) 到 (50, 50) 到 (90, 10) 再回到 (10, 10)。
* **Fill Color:**  红色 (通过 CSS 或 HTML 属性设置)
* **Stroke Color:** 蓝色 (通过 CSS 或 HTML 属性设置)
* **Stroke Width:** 2px (通过 CSS 或 HTML 属性设置)
* **Transform:** 无变换

**逻辑推理过程 (SVGShapePainter 的行为):**

1. **`Paint()` 方法被调用:** 检查可见性、裁剪等，假设都满足绘制条件。
2. **`ScopedSVGTransformState`:**  由于没有变换，这个步骤可能不会做太多事情。
3. **`ScopedSVGPaintState`:**  设置填充颜色为红色，描边颜色为蓝色，描边宽度为 2px。
4. **`PaintShape()` 方法被调用:**
    * **填充:**  由于有填充，`FillShape()` 方法会被调用，使用红色填充三角形的区域。
    * **描边:**  由于有描边，`StrokeShape()` 方法会被调用，使用蓝色描绘三角形的轮廓，描边宽度为 2px。
    * **标记:** 假设没有定义标记，则跳过 `PaintMarkers()`。

**假设输出 (屏幕上的渲染结果):**

一个红色的实心三角形，其边缘有一条蓝色的、2px 宽的描边。

**涉及用户或者编程常见的使用错误:**

1. **错误的 SVG 语法:**  如果 `<path>` 元素的 `d` 属性包含错误的路径数据，`SVGShapePainter` 可能会绘制出意想不到的形状，甚至导致渲染错误。
    * **例子:** `<path d="M 10 10 L 50 A 30 30 0 0 1 90 10 Z" fill="red" />`  这里 `L 50` 缺少了 y 坐标。
2. **CSS 属性值错误:**  提供无效的 CSS 属性值可能会导致渲染问题。
    * **例子:** `stroke-width: abc;`  `abc` 不是一个有效的长度单位。
3. **性能问题:**  绘制非常复杂的 SVG 路径或使用大量的滤镜可能会导致性能下降，用户可能会感觉到页面卡顿。
4. **忘记设置填充或描边:**  如果既没有设置 `fill` 也没有设置 `stroke`，形状可能不可见。
5. **`fill-rule` 理解错误:**  不理解 `evenodd` 和 `nonzero` 填充规则的区别，可能会导致复杂的自相交路径填充不符合预期。
6. **`non-scaling-stroke` 使用不当:**  如果错误地使用了 `vector-effect="non-scaling-stroke"`，可能会导致在缩放时描边宽度看起来不一致。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在浏览器中访问了一个包含以下 SVG 的网页，并且开发者想要调试这个矩形的绘制过程：

```html
<svg width="200" height="100">
  <rect id="myRect" x="20" y="10" width="160" height="80" fill="yellow" stroke="black" stroke-width="2" />
</svg>
```

**调试步骤和线索:**

1. **用户加载网页:** 浏览器解析 HTML，创建 DOM 树。
2. **布局阶段:** Blink 的布局引擎会创建 `LayoutSVGRoot` 和 `LayoutSVGShape` 对象来表示 `<svg>` 和 `<rect>` 元素。`LayoutSVGShape` 对象会计算出矩形的几何信息（位置、尺寸）。
3. **绘制阶段:**
    * 当需要绘制 `myRect` 这个元素时，Blink 的绘制引擎会创建一个 `SVGShapePainter` 对象，并将对应的 `LayoutSVGShape` 对象传递给它。
    * **调试线索 1:**  开发者可以在 `SVGShapePainter::Paint()` 方法入口处设置断点，查看传入的 `LayoutSVGShape` 对象的信息，例如 `ObjectBoundingBox()` 返回的矩形边界。
    * `SVGShapePainter::Paint()` 会检查可见性等条件。
    * **调试线索 2:** 检查 `layout_svg_shape_.StyleRef().Visibility()` 的值，确认元素是否可见。
    * `ScopedSVGTransformState` 会处理变换。
    * `ScopedSVGPaintState` 会根据 CSS 样式设置绘制状态。
    * **调试线索 3:**  检查 `layout_svg_shape_.StyleRef()` 获取的 `ComputedStyle` 对象，确认 `fill`, `stroke`, `stroke-width` 等 CSS 属性是否正确解析。
    * `SVGShapePainter::PaintShape()` 会被调用。
    * 如果有填充，`SVGShapePainter::FillShape()` 会被调用。
    * **调试线索 4:**  在 `FillShape()` 中查看 `flags` 参数，确认填充颜色是否正确。
    * 如果有描边，`SVGShapePainter::StrokeShape()` 会被调用。
    * **调试线索 5:** 在 `StrokeShape()` 中查看 `flags` 参数，确认描边颜色和宽度是否正确。还可以检查 `layout_svg_shape_.DashScaleFactor()` 等与描边相关的属性。
    * 如果定义了标记，`SVGShapePainter::PaintMarkers()` 会被调用。
    * **调试线索 6:**  检查 `layout_svg_shape_.MarkerPositions()` 获取的标记位置信息，以及 `style.MarkerStartResource()`, `style.MarkerMidResource()`, `style.MarkerEndResource()` 获取的标记引用。
4. **GPU 渲染:**  `GraphicsContext` 记录的绘制指令最终会传递给 GPU 进行渲染。

通过在 `SVGShapePainter` 的关键方法中设置断点，并检查相关的 `LayoutSVGShape` 对象和 `ComputedStyle` 信息，开发者可以逐步追踪 SVG 形状的绘制过程，找出渲染问题的根源。例如，如果矩形的颜色不正确，可能是 CSS 样式没有正确应用，或者 `PaintFlags` 的设置有问题。如果矩形的位置或尺寸不正确，可能是在布局阶段计算错误，或者变换没有正确应用。

Prompt: 
```
这是目录为blink/renderer/core/paint/svg_shape_painter.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/svg_shape_painter.h"

#include "base/types/optional_util.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_resource_marker.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_shape.h"
#include "third_party/blink/renderer/core/layout/svg/svg_layout_support.h"
#include "third_party/blink/renderer/core/layout/svg/svg_marker_data.h"
#include "third_party/blink/renderer/core/layout/svg/svg_resources.h"
#include "third_party/blink/renderer/core/paint/paint_auto_dark_mode.h"
#include "third_party/blink/renderer/core/paint/paint_info.h"
#include "third_party/blink/renderer/core/paint/scoped_svg_paint_state.h"
#include "third_party/blink/renderer/core/paint/svg_container_painter.h"
#include "third_party/blink/renderer/core/paint/svg_model_object_painter.h"
#include "third_party/blink/renderer/core/paint/svg_object_painter.h"
#include "third_party/blink/renderer/core/paint/timing/paint_timing.h"
#include "third_party/blink/renderer/core/style/paint_order_array.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context_state_saver.h"
#include "third_party/blink/renderer/platform/graphics/paint/drawing_recorder.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_record.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_record_builder.h"
#include "third_party/blink/renderer/platform/graphics/stroke_data.h"
#include "third_party/skia/include/core/SkPath.h"
#include "ui/gfx/geometry/skia_conversions.h"

namespace blink {

static std::optional<AffineTransform> SetupNonScalingStrokeContext(
    const LayoutSVGShape& layout_svg_shape,
    GraphicsContextStateSaver& state_saver) {
  const AffineTransform& non_scaling_stroke_transform =
      layout_svg_shape.NonScalingStrokeTransform();
  if (!non_scaling_stroke_transform.IsInvertible())
    return std::nullopt;
  state_saver.Save();
  state_saver.Context().ConcatCTM(non_scaling_stroke_transform.Inverse());
  return non_scaling_stroke_transform;
}

void SVGShapePainter::Paint(const PaintInfo& paint_info) {
  if (paint_info.phase != PaintPhase::kForeground ||
      layout_svg_shape_.StyleRef().Visibility() != EVisibility::kVisible ||
      layout_svg_shape_.IsShapeEmpty()) {
    return;
  }

  if (SVGModelObjectPainter::CanUseCullRect(layout_svg_shape_.StyleRef())) {
    if (!paint_info.GetCullRect().IntersectsTransformed(
            layout_svg_shape_.LocalSVGTransform(),
            layout_svg_shape_.VisualRectInLocalSVGCoordinates()))
      return;
  }
  // Shapes cannot have children so do not call TransformCullRect.

  ScopedSVGTransformState transform_state(paint_info, layout_svg_shape_);
  const PaintInfo& content_paint_info = transform_state.ContentPaintInfo();

  {
    ScopedSVGPaintState paint_state(layout_svg_shape_, content_paint_info);
    SVGModelObjectPainter::RecordHitTestData(layout_svg_shape_,
                                             content_paint_info);
    SVGModelObjectPainter::RecordRegionCaptureData(layout_svg_shape_,
                                                   content_paint_info);
    if (!DrawingRecorder::UseCachedDrawingIfPossible(
            content_paint_info.context, layout_svg_shape_,
            content_paint_info.phase)) {
      SVGDrawingRecorder recorder(content_paint_info.context, layout_svg_shape_,
                                  content_paint_info.phase);
      PaintShape(content_paint_info);
    }
  }

  SVGModelObjectPainter(layout_svg_shape_).PaintOutline(content_paint_info);
}

void SVGShapePainter::PaintShape(const PaintInfo& paint_info) {
  const ComputedStyle& style = layout_svg_shape_.StyleRef();
  const bool should_anti_alias =
      style.ShapeRendering() != EShapeRendering::kCrispedges &&
      style.ShapeRendering() != EShapeRendering::kOptimizespeed;

  if (paint_info.IsRenderingClipPathAsMaskImage()) {
    cc::PaintFlags clip_flags;
    clip_flags.setColor(SK_ColorBLACK);
    clip_flags.setAntiAlias(should_anti_alias);
    FillShape(paint_info.context, clip_flags, style.ClipRule());
    return;
  }

  const PaintOrderArray paint_order(style.PaintOrder());
  for (unsigned i = 0; i < 3; i++) {
    switch (paint_order[i]) {
      case PT_FILL: {
        if (SVGObjectPainter::HasFill(style,
                                      paint_info.GetSvgContextPaints())) {
          cc::PaintFlags fill_flags;
          if (!SVGObjectPainter(layout_svg_shape_,
                                paint_info.GetSvgContextPaints())
                   .PreparePaint(paint_info.GetPaintFlags(), style,
                                 kApplyToFillMode, fill_flags)) {
            break;
          }
          fill_flags.setAntiAlias(should_anti_alias);
          FillShape(paint_info.context, fill_flags, style.FillRule());
        }
        break;
      }
      case PT_STROKE:
        if (SVGObjectPainter::HasVisibleStroke(
                style, paint_info.GetSvgContextPaints())) {
          GraphicsContextStateSaver state_saver(paint_info.context, false);
          std::optional<AffineTransform> non_scaling_transform;

          if (layout_svg_shape_.HasNonScalingStroke()) {
            // Non-scaling stroke needs to reset the transform back to the
            // host transform.
            non_scaling_transform =
                SetupNonScalingStrokeContext(layout_svg_shape_, state_saver);
            if (!non_scaling_transform) {
              return;
            }
          }

          cc::PaintFlags stroke_flags;
          if (!SVGObjectPainter(layout_svg_shape_,
                                paint_info.GetSvgContextPaints())
                   .PreparePaint(paint_info.GetPaintFlags(), style,
                                 kApplyToStrokeMode, stroke_flags,
                                 base::OptionalToPtr(non_scaling_transform))) {
            break;
          }
          stroke_flags.setAntiAlias(should_anti_alias);

          StrokeData stroke_data;
          SVGLayoutSupport::ApplyStrokeStyleToStrokeData(
              stroke_data, style, layout_svg_shape_,
              layout_svg_shape_.DashScaleFactor());
          stroke_data.SetupPaint(&stroke_flags);

          StrokeShape(paint_info.context, stroke_flags);
        }
        break;
      case PT_MARKERS:
        PaintMarkers(paint_info);
        break;
      default:
        NOTREACHED();
    }
  }
}

class PathWithTemporaryWindingRule {
  STACK_ALLOCATED();

 public:
  PathWithTemporaryWindingRule(Path& path, SkPathFillType fill_type)
      : path_(const_cast<SkPath&>(path.GetSkPath())) {
    saved_fill_type_ = path_.getFillType();
    path_.setFillType(fill_type);
  }
  ~PathWithTemporaryWindingRule() { path_.setFillType(saved_fill_type_); }

  const SkPath& GetSkPath() const { return path_; }

 private:
  SkPath& path_;
  SkPathFillType saved_fill_type_;
};

void SVGShapePainter::FillShape(GraphicsContext& context,
                                const cc::PaintFlags& flags,
                                WindRule wind_rule) {
  const SkPathFillType sk_fill_type = WebCoreWindRuleToSkFillType(wind_rule);
  AutoDarkMode auto_dark_mode(PaintAutoDarkMode(
      layout_svg_shape_.StyleRef(), DarkModeFilter::ElementRole::kSVG));
  switch (layout_svg_shape_.GetGeometryType()) {
    case LayoutSVGShape::GeometryType::kRectangle:
      context.DrawRect(
          gfx::RectFToSkRect(layout_svg_shape_.ObjectBoundingBox()), flags,
          auto_dark_mode);
      break;
    case LayoutSVGShape::GeometryType::kCircle:
    case LayoutSVGShape::GeometryType::kEllipse:
      context.DrawOval(
          gfx::RectFToSkRect(layout_svg_shape_.ObjectBoundingBox()), flags,
          auto_dark_mode);
      break;
    default: {
      DCHECK(layout_svg_shape_.HasPath());
      PathWithTemporaryWindingRule path_with_winding(
          layout_svg_shape_.GetPath(), sk_fill_type);
      context.DrawPath(path_with_winding.GetSkPath(), flags, auto_dark_mode);
    }
  }
  PaintTiming& timing = PaintTiming::From(layout_svg_shape_.GetDocument());
  timing.MarkFirstContentfulPaint();
}

void SVGShapePainter::StrokeShape(GraphicsContext& context,
                                  const cc::PaintFlags& flags) {
  AutoDarkMode auto_dark_mode(PaintAutoDarkMode(
      layout_svg_shape_.StyleRef(), DarkModeFilter::ElementRole::kSVG));

  // Remap all geometry types to 'path' when non-scaling-stroke is in effect.
  LayoutSVGShape::GeometryType geometry_type =
      layout_svg_shape_.GetGeometryType();
  if (layout_svg_shape_.HasNonScalingStroke()) {
    geometry_type = LayoutSVGShape::GeometryType::kPath;
  }

  switch (geometry_type) {
    case LayoutSVGShape::GeometryType::kRectangle:
      context.DrawRect(
          gfx::RectFToSkRect(layout_svg_shape_.ObjectBoundingBox()), flags,
          auto_dark_mode);
      break;
    case LayoutSVGShape::GeometryType::kCircle:
    case LayoutSVGShape::GeometryType::kEllipse:
      context.DrawOval(
          gfx::RectFToSkRect(layout_svg_shape_.ObjectBoundingBox()), flags,
          auto_dark_mode);
      break;
    default:
      DCHECK(layout_svg_shape_.HasPath());
      const Path* use_path = &layout_svg_shape_.GetPath();
      if (layout_svg_shape_.HasNonScalingStroke())
        use_path = &layout_svg_shape_.NonScalingStrokePath();
      context.DrawPath(use_path->GetSkPath(), flags, auto_dark_mode);
  }
  PaintTiming& timing = PaintTiming::From(layout_svg_shape_.GetDocument());
  timing.MarkFirstContentfulPaint();
}

void SVGShapePainter::PaintMarkers(const PaintInfo& paint_info) {
  const Vector<MarkerPosition>* marker_positions =
      layout_svg_shape_.MarkerPositions();
  if (!marker_positions || marker_positions->empty())
    return;
  SVGResourceClient* client = SVGResources::GetClient(layout_svg_shape_);
  const ComputedStyle& style = layout_svg_shape_.StyleRef();
  auto* marker_start = GetSVGResourceAsType<LayoutSVGResourceMarker>(
      *client, style.MarkerStartResource());
  auto* marker_mid = GetSVGResourceAsType<LayoutSVGResourceMarker>(
      *client, style.MarkerMidResource());
  auto* marker_end = GetSVGResourceAsType<LayoutSVGResourceMarker>(
      *client, style.MarkerEndResource());
  if (!marker_start && !marker_mid && !marker_end)
    return;

  const float stroke_width = layout_svg_shape_.StrokeWidthForMarkerUnits();

  for (const MarkerPosition& marker_position : *marker_positions) {
    if (LayoutSVGResourceMarker* marker = marker_position.SelectMarker(
            marker_start, marker_mid, marker_end)) {
      PaintMarker(paint_info, *marker, marker_position, stroke_width);
    }
  }
}

void SVGShapePainter::PaintMarker(const PaintInfo& paint_info,
                                  LayoutSVGResourceMarker& marker,
                                  const MarkerPosition& position,
                                  float stroke_width) {
  marker.ClearInvalidationMask();

  if (!marker.ShouldPaint())
    return;

  AffineTransform transform =
      marker.MarkerTransformation(position, stroke_width);

  cc::PaintCanvas* canvas = paint_info.context.Canvas();

  canvas->save();
  canvas->concat(AffineTransformToSkM44(transform));
  if (SVGLayoutSupport::IsOverflowHidden(marker))
    canvas->clipRect(gfx::RectFToSkRect(marker.Viewport()));
  PaintRecordBuilder builder(paint_info.context);
  // It's expensive to track the transformed paint cull rect for each
  // marker so just disable culling. The shape paint call will already
  // be culled if it is outside the paint info cull rect.
  auto* context_paints = paint_info.GetSvgContextPaints();
  if (context_paints) {
    transform.PostConcat(context_paints->transform);
  }
  SVGObjectPainter object_painter(layout_svg_shape_, context_paints);
  SvgContextPaints marker_context_paints(
      object_painter.ResolveContextPaint(
          layout_svg_shape_.StyleRef().FillPaint()),
      object_painter.ResolveContextPaint(
          layout_svg_shape_.StyleRef().StrokePaint()),
      transform);
  PaintInfo marker_paint_info(
      builder.Context(), CullRect::Infinite(), paint_info.phase,
      paint_info.DescendantPaintingBlocked(), paint_info.GetPaintFlags(),
      &marker_context_paints);
  SVGContainerPainter(marker).Paint(marker_paint_info);
  builder.EndRecording(*canvas);

  canvas->restore();
}

}  // namespace blink

"""

```