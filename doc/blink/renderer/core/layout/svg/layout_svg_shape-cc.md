Response:
Let's break down the thought process for analyzing the `LayoutSVGShape.cc` file and answering the prompt.

**1. Understanding the Goal:**

The primary goal is to understand the purpose of this specific Chromium Blink file and how it interacts with web technologies (HTML, CSS, JavaScript). The prompt also asks for examples, logical reasoning with inputs/outputs, and common usage errors.

**2. Initial Code Scan and High-Level Understanding:**

* **Copyright Notices:** Indicate ownership and licensing. Not directly functional but important for legal reasons.
* **Includes:**  These are the key to understanding the file's dependencies and what it *does*. Look for keywords:
    * `layout/`:  Indicates this file is part of Blink's layout engine, responsible for positioning and sizing elements.
    * `svg/`:  Confirms this file is specifically for SVG elements.
    * `paint/`:  Suggests interaction with the painting process (drawing).
    * `core/`:  Indicates core Blink functionality.
    * `svg/svg_geometry_element.h`:  This is a crucial include, telling us this class deals with the *shapes* within SVG (path, circle, etc.).
    * `platform/graphics/`: Interaction with the underlying graphics system.
* **Class Declaration:** `LayoutSVGShape`. This is the main class this file defines. The name strongly suggests it's responsible for the layout of SVG shape elements.
* **Member Variables:** Glance at the member variables. Keywords like `geometry_type_`, `needs_boundaries_update_`, `path_`, `transform_`, `fill_bounding_box_`, `stroke_path_cache_` provide hints about what the class manages. "Bounding box," "path," and "transform" are key concepts in SVG.
* **Methods:** Quickly scan the public methods. Names like `StyleDidChange`, `UpdateSVGLayout`, `Paint`, `HitTestShape`, `FillContains`, `StrokeContains`, `StrokeWidth` give a good sense of the functionalities. These seem related to responding to style changes, performing layout calculations, drawing the shape, and handling hit testing (determining if a point is inside the shape).

**3. Deeper Analysis - Function by Function (or Group of Related Functions):**

* **Constructor/Destructor:** Basic object lifecycle management.
* **`StyleDidChange`:**  This is a core layout concept. It signifies that the element's CSS styles have changed. Notice how it triggers updates for boundaries, transforms, and paints. It also handles invalidating caches based on style changes. *Connection to CSS*.
* **`WillBeDestroyed`:**  Cleanup when the object is no longer needed.
* **`ClearPath`/`CreatePath`:**  Managing the internal representation of the SVG shape's geometry (the `Path` object). *Connection to SVG's `<path>` element and other shape primitives*.
* **`DashScaleFactor`:** Deals with dashed strokes and how they scale. *Connection to CSS `stroke-dasharray` and potentially SVG's `pathLength`*.
* **`ApproximateStrokeBoundingBox`/`HitTestStrokeBoundingBox`/`StrokeBoundingBox`:** These functions are crucial for determining the boundaries of the shape, especially considering the stroke. Notice the different levels of precision (approximation vs. exact calculation). *Connection to CSS `stroke-width` and related properties*.
* **`ShapeDependentStrokeContains`/`ShapeDependentFillContains`:** These are the core hit-testing logic using the shape's geometry. *Connection to user interaction and event handling in JavaScript*.
* **`FillContains`/`StrokeContains`:** Higher-level hit-testing functions that incorporate style properties (fill, stroke) and bounding box checks for optimization. *Connection to user interaction and event handling in JavaScript and the visual rendering based on CSS*.
* **`UpdateSVGLayout`:**  The heart of the layout process for SVG shapes. It manages updates to the shape's geometry, bounding boxes, and transforms. It's triggered during the layout phase.
* **`UpdateAfterSVGLayout`:**  Further updates performed after the main layout pass, often related to transforms and non-scaling strokes.
* **`ComputeRootTransform`/`ComputeNonScalingStrokeTransform`:**  Calculating the necessary transformations for rendering and special effects like `vector-effect: non-scaling-stroke`. *Strong connection to CSS `transform` and `vector-effect`*.
* **`UpdateNonScalingStrokeData`:**  Specifically handles the non-scaling stroke effect.
* **`Paint`:**  The function responsible for drawing the SVG shape. It uses the `SVGShapePainter`.
* **`NodeAtPoint`/`HitTestShape`:** The main hit-testing entry point and the core logic to determine if a point lies within the shape, considering fills, strokes, and pointer events. *Direct connection to JavaScript event handling (e.g., `click`, `mouseover`) on SVG elements*.
* **`CalculateStrokeBoundingBox`/`CalculateNonScalingStrokeBoundingBox`:** Calculate the bounding box considering the stroke.
* **`StrokeWidth`/`StrokeWidthForMarkerUnits`:** Functions to retrieve and potentially adjust the stroke width based on context. *Connection to CSS `stroke-width` and SVG markers*.
* **`EnsureRareData`:**  A common pattern for lazy initialization of less frequently used data.
* **`VisualRectOutsetForRasterEffects`:** Deals with optimizations for rasterization, especially related to hairline strokes.

**4. Identifying Relationships with HTML, CSS, and JavaScript:**

* **HTML:** The SVG elements themselves (`<path>`, `<circle>`, etc.) are defined in HTML. This file directly handles the layout and rendering of these elements.
* **CSS:**  Many methods directly interact with the `ComputedStyle` object, which holds the CSS properties applied to the element. Examples: `StyleDidChange`, `StrokeWidth`, checking for `stroke`, `fill`, `stroke-dasharray`, `transform`, `vector-effect`.
* **JavaScript:** The hit-testing functionality is crucial for making SVG elements interactive. When a user clicks or hovers over an SVG shape, the browser uses code like this to determine which element was targeted. JavaScript event listeners then react to these events.

**5. Formulating Examples, Assumptions, and Common Errors:**

* **Examples:**  Think about concrete SVG code snippets and how this C++ code would handle them. Consider different shapes, strokes, fills, and transformations.
* **Assumptions and Logic:**  Trace the flow of execution for specific scenarios. For instance, what happens when a style changes? What are the inputs and outputs of the hit-testing functions?
* **Common Errors:**  Consider mistakes developers might make when working with SVG and how the browser handles them. Think about incorrect CSS values, missing attributes, or misunderstandings about how SVG properties work.

**6. Structuring the Answer:**

Organize the information logically based on the prompt's requirements:

* **Functionality:** Provide a concise summary of the file's purpose.
* **Relationships with Web Technologies:** Clearly explain the connections to HTML, CSS, and JavaScript, providing specific examples.
* **Logical Reasoning:** Present clear assumptions, inputs, and outputs for illustrative scenarios.
* **Common Errors:**  Give practical examples of mistakes developers might make.

**Self-Correction/Refinement during the Process:**

* **Initial Over-generalization:**  At first, one might just say "it lays out SVG shapes."  The deeper analysis reveals the nuances: handling strokes, fills, transforms, hit-testing, caching, etc.
* **Focusing too much on code details:**  Avoid getting bogged down in every line of code. Focus on the *purpose* of the methods and how they relate to the bigger picture of web rendering.
* **Missing connections:** Actively look for links between the C++ code and the web technologies. Think about which CSS properties affect which methods, or how JavaScript events trigger the hit-testing logic.

By following this structured approach, analyzing the code in chunks, and continually connecting the C++ implementation to the user-facing web technologies, it's possible to generate a comprehensive and accurate answer to the prompt.
这个文件 `blink/renderer/core/layout/svg/layout_svg_shape.cc` 是 Chromium Blink 渲染引擎中负责 **SVG 形状元素 (如 `<rect>`, `<circle>`, `<path>`, `<ellipse>`, `<line>`, `<polygon>`, `<polyline>`) 的布局和渲染** 的核心代码。

以下是它的主要功能：

**1. 管理 SVG 形状的几何信息：**

*   **存储和更新形状路径 (Path)：**  `LayoutSVGShape` 对象会根据对应的 SVG 元素 (`SVGGeometryElement`) 创建并维护一个 `Path` 对象，该对象描述了形状的几何轮廓。当 SVG 元素的几何属性发生变化时（例如，`<rect>` 的 `width` 或 `<path>` 的 `d` 属性），这个 `Path` 对象会被更新。
*   **计算和缓存边界框 (Bounding Boxes)：**
    *   **Fill Bounding Box：** 计算形状填充区域的最小外接矩形。
    *   **Stroke Bounding Box：** 计算形状描边区域的最小外接矩形。这会考虑 `stroke-width`、`stroke-linecap`、`stroke-linejoin` 和 `stroke-miterlimit` 等 CSS 属性。
    *   **Decorated Bounding Box：**  包含填充和描边的总边界框。
*   **处理变换 (Transforms)：**  管理应用于形状的变换，包括 CSS `transform` 属性和 SVG 特有的变换属性（例如，`transform` 属性）。

**2. 支持 SVG 渲染：**

*   **绘制形状 (Painting)：**  `Paint` 方法负责调用 `SVGShapePainter` 来实际绘制 SVG 形状。这包括填充颜色、描边颜色、渐变、图案等。
*   **处理描边 (Stroke)：**  计算描边的路径，考虑描边的宽度、线帽、线连接、虚线等 CSS 属性。它会缓存描边路径以提高性能。
*   **处理填充 (Fill)：**  确定如何填充形状的内部区域。

**3. 实现 SVG 特有的布局逻辑：**

*   **响应样式变化 (StyleDidChange)：**  当 SVG 形状元素的 CSS 样式发生变化时，该方法会被调用。它会根据样式变化的影响来决定是否需要重新计算布局、更新边界框、或重新绘制。
*   **处理非缩放描边 (Non-Scaling Stroke)：**  支持 `vector-effect: non-scaling-stroke` CSS 属性，该属性使得描边的宽度在缩放变换下保持不变。
*   **计算虚线比例因子 (Dash Scale Factor)：**  用于正确计算虚线的长度。

**4. 支持事件处理和命中测试 (Hit Testing)：**

*   **`NodeAtPoint` 和 `HitTestShape`：**  这些方法用于判断屏幕上的一个点是否在 SVG 形状的内部或描边上。这对于处理鼠标事件（例如 `click`, `mouseover`）至关重要。
*   **考虑 `pointer-events` CSS 属性：**  根据元素的 `pointer-events` 属性来决定是否可以被点击。

**5. 资源管理：**

*   **与 `SVGResources` 交互：**  处理 SVG 资源（例如渐变、图案）的更新和失效。

**与 JavaScript, HTML, CSS 的关系：**

*   **HTML:**  `LayoutSVGShape` 对象对应于 HTML 中的 SVG 形状元素 (如 `<rect>`, `<circle>`, `<path>` 等)。当浏览器解析 HTML 并遇到这些元素时，Blink 引擎会创建相应的 `LayoutSVGShape` 对象。
    *   **举例：**  HTML 中有一个 `<rect width="100" height="50" fill="red"/>` 元素，Blink 会创建一个 `LayoutSVGShape` 对象来表示这个矩形，并根据 `width` 和 `height` 计算其初始边界框。
*   **CSS:**  CSS 样式直接影响 `LayoutSVGShape` 对象的行为和渲染结果。
    *   **举例：**  CSS 规则 `.my-rect { stroke: blue; stroke-width: 2px; }` 会导致与该 CSS 类关联的 `<rect>` 元素的 `LayoutSVGShape` 对象更新其描边颜色和宽度。`StyleDidChange` 方法会被调用，并且可能会触发边界框的重新计算。
    *   **举例：**  CSS `transform: rotate(45deg);` 应用于一个 `<circle>` 元素时，`LayoutSVGShape` 对象会更新其内部的变换矩阵，并在绘制时应用旋转。
*   **JavaScript:**  JavaScript 可以操作 SVG 形状元素的属性和样式，从而间接地影响 `LayoutSVGShape` 对象。
    *   **举例：**  JavaScript 代码 `document.getElementById("myCircle").setAttribute("cx", 75);` 会修改 `<circle>` 元素的 `cx` 属性。Blink 引擎会接收到这个变化，并更新对应 `LayoutSVGShape` 对象的几何信息，可能需要重新计算边界框并触发重绘。
    *   **举例：**  JavaScript 可以添加事件监听器到 SVG 形状元素上。当用户点击形状时，Blink 引擎会使用 `NodeAtPoint` 和 `HitTestShape` 等方法来确定点击事件发生在哪个 `LayoutSVGShape` 对象上，然后将事件传递给 JavaScript 代码。

**逻辑推理、假设输入与输出：**

**假设输入：**

1. 一个 `<rect>` 元素，HTML 代码如下：`<rect id="myRect" x="10" y="20" width="100" height="50" fill="green" stroke="black" stroke-width="3"/>`
2. 相关的 CSS 规则：`#myRect { transform: translate(20px, 10px); }`

**逻辑推理：**

*   当浏览器解析到 `<rect>` 元素时，会创建一个 `LayoutSVGShape` 对象。
*   `UpdateSVGLayout` 方法会被调用来计算初始布局。
*   根据 HTML 属性 `x`, `y`, `width`, `height`，计算出初始的填充边界框 (Fill Bounding Box)。假设为 `(10, 20, 100, 50)`。
*   根据 CSS 样式 `stroke-width: 3`，计算描边边界框。会比填充边界框向外扩展 `stroke-width / 2`，即 1.5px。假设描边边界框为 `(8.5, 18.5, 103, 53)`。
*   根据 CSS `transform: translate(20px, 10px)`，计算局部变换矩阵。
*   在绘制阶段，会将局部变换应用于形状，使得矩形在屏幕上的位置发生偏移。
*   当进行命中测试时，例如用户点击屏幕上的某个点，需要将屏幕坐标转换到 SVG 元素的局部坐标系下，然后判断该点是否在填充或描边区域内。

**假设输出：**

*   `LayoutSVGShape` 对象的 `fill_bounding_box_` 可能为 `(10, 20, 100, 50)`。
*   `LayoutSVGShape` 对象的 `decorated_bounding_box_` （考虑描边）可能为 `(8.5, 18.5, 103, 53)`。
*   `LayoutSVGShape` 对象的局部变换 `local_transform_` 会包含平移 `(20, 10)`。
*   如果用户点击屏幕坐标 `(50, 50)`，经过逆变换后，可能对应到矩形局部坐标系内的某个点。`HitTestShape` 方法会判断该点是否在矩形的填充区域或描边区域内。

**用户或编程常见的使用错误：**

1. **误解 SVG 坐标系统和变换：**  开发者可能会对 SVG 的用户空间和视口概念，以及 `transform` 属性的作用方式理解不足，导致形状显示位置或大小不符合预期。
    *   **例子：**  在一个嵌套的 SVG 结构中，忘记考虑父元素的变换，导致子元素的变换效果出错。
2. **`stroke-width` 的单位问题：**  如果没有明确指定单位，`stroke-width` 的默认单位是用户单位。在某些情况下，这可能导致在不同缩放级别下描边宽度看起来不一致。
3. **`pointer-events` 的滥用或误用：**  错误地设置 `pointer-events` 属性可能导致元素无法响应鼠标事件，或者意外地拦截了其他元素的事件。
    *   **例子：**  将一个覆盖在其他可点击元素之上的 SVG 元素的 `pointer-events` 设置为 `auto`，可能导致下方的元素无法被点击。
4. **忘记更新 SVG 属性或样式：**  在 JavaScript 中动态修改 SVG 元素的属性或样式后，如果没有触发浏览器的重绘或重新布局，可能导致界面没有更新。
5. **性能问题：**  对于复杂的 SVG 形状或动画，频繁地修改其属性可能导致性能问题。浏览器需要不断地重新计算布局和绘制。
6. **与 CSS 动画/过渡的冲突：**  在某些情况下，使用 CSS 动画或过渡来改变 SVG 形状的几何属性可能会导致意外的渲染结果，因为布局和绘制过程可能与动画/过渡的效果相互影响。
7. **不理解 `fill-rule` 和 `clip-rule`：**  对于复杂的路径，`fill-rule` (evenodd 或 nonzero) 的选择会影响如何填充形状的内部区域。类似地，`clip-rule` 影响剪切路径的效果。不理解这些规则可能导致形状的填充或剪切效果不正确。

总而言之，`blink/renderer/core/layout/svg/layout_svg_shape.cc` 文件在 Chromium Blink 渲染引擎中扮演着至关重要的角色，它负责将 SVG 形状元素的声明式描述 (HTML 和 CSS) 转换为浏览器可以渲染和交互的图形表示。它涉及到复杂的几何计算、布局逻辑和渲染机制，并与 JavaScript, HTML 和 CSS 紧密配合，共同构建出丰富的 Web 页面。

Prompt: 
```
这是目录为blink/renderer/core/layout/svg/layout_svg_shape.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 2004, 2005, 2007 Nikolas Zimmermann <zimmermann@kde.org>
 * Copyright (C) 2004, 2005, 2008 Rob Buis <buis@kde.org>
 * Copyright (C) 2005, 2007 Eric Seidel <eric@webkit.org>
 * Copyright (C) 2009 Google, Inc.
 * Copyright (C) 2009 Dirk Schulze <krit@webkit.org>
 * Copyright (C) Research In Motion Limited 2010. All rights reserved.
 * Copyright (C) 2009 Jeff Schiller <codedread@gmail.com>
 * Copyright (C) 2011 Renata Hodovan <reni@webkit.org>
 * Copyright (C) 2011 University of Szeged
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#include "third_party/blink/renderer/core/layout/svg/layout_svg_shape.h"

#include "third_party/blink/renderer/core/layout/hit_test_location.h"
#include "third_party/blink/renderer/core/layout/hit_test_result.h"
#include "third_party/blink/renderer/core/layout/pointer_events_hit_rules.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_resource_paint_server.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_root.h"
#include "third_party/blink/renderer/core/layout/svg/svg_layout_info.h"
#include "third_party/blink/renderer/core/layout/svg/svg_layout_support.h"
#include "third_party/blink/renderer/core/layout/svg/svg_resources.h"
#include "third_party/blink/renderer/core/layout/svg/transform_helper.h"
#include "third_party/blink/renderer/core/layout/svg/transformed_hit_test_location.h"
#include "third_party/blink/renderer/core/paint/clip_path_clipper.h"
#include "third_party/blink/renderer/core/paint/svg_shape_painter.h"
#include "third_party/blink/renderer/core/svg/svg_geometry_element.h"
#include "third_party/blink/renderer/core/svg/svg_length_functions.h"
#include "third_party/blink/renderer/platform/graphics/stroke_data.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"
#include "ui/gfx/geometry/point_f.h"

namespace blink {

namespace {

void ClampBoundsToFinite(gfx::RectF& bounds) {
  bounds.set_x(ClampTo<float>(bounds.x()));
  bounds.set_y(ClampTo<float>(bounds.y()));
  bounds.set_width(ClampTo<float>(bounds.width()));
  bounds.set_height(ClampTo<float>(bounds.height()));
}

}  // namespace

LayoutSVGShape::LayoutSVGShape(SVGGeometryElement* node)
    : LayoutSVGModelObject(node),
      // A description (classification) of what geometric shape is represented -
      // used for computing stroke bounds more efficiently, fast-paths for
      // painting and determining if a shape is "empty".
      geometry_type_(GeometryType::kEmpty),
      // Default is false, the cached rects are empty from the beginning.
      needs_boundaries_update_(false),
      // Default is true, so we grab a Path object once from SVGGeometryElement.
      needs_shape_update_(true),
      // Default is true, so we grab a AffineTransform object once from
      // SVGGeometryElement.
      needs_transform_update_(true),
      transform_uses_reference_box_(false) {}

LayoutSVGShape::~LayoutSVGShape() = default;

void LayoutSVGShape::StyleDidChange(StyleDifference diff,
                                    const ComputedStyle* old_style) {
  NOT_DESTROYED();
  LayoutSVGModelObject::StyleDidChange(diff, old_style);

  if (diff.NeedsFullLayout()) {
    SetNeedsBoundariesUpdate();
  }

  TransformHelper::UpdateOffsetPath(*GetElement(), old_style);
  transform_uses_reference_box_ =
      TransformHelper::UpdateReferenceBoxDependency(*this);
  SVGResources::UpdatePaints(*this, old_style, StyleRef());

  if (old_style) {
    const ComputedStyle& style = StyleRef();
    // Most of the stroke attributes (caps, joins, miters, width, etc.) will
    // cause a re-layout which will clear the stroke-path cache; however, there
    // are a couple of additional properties that *won't* cause a layout, but
    // are significant enough to require invalidating the cache.
    if (!diff.NeedsFullLayout() && stroke_path_cache_) {
      if (old_style->StrokeDashOffset() != style.StrokeDashOffset() ||
          *old_style->StrokeDashArray() != *style.StrokeDashArray()) {
        stroke_path_cache_.reset();
      }
    }

    if (transform_uses_reference_box_ && !needs_transform_update_) {
      if (TransformHelper::CheckReferenceBoxDependencies(*old_style, style)) {
        SetNeedsTransformUpdate();
        SetNeedsPaintPropertyUpdate();
      }
    }
  }

  SetTransformAffectsVectorEffect(HasNonScalingStroke());
}

void LayoutSVGShape::WillBeDestroyed() {
  NOT_DESTROYED();
  SVGResources::ClearPaints(*this, Style());
  LayoutSVGModelObject::WillBeDestroyed();
}

void LayoutSVGShape::ClearPath() {
  NOT_DESTROYED();
  path_.reset();
  stroke_path_cache_.reset();
}

void LayoutSVGShape::CreatePath() {
  NOT_DESTROYED();
  if (!path_)
    path_ = std::make_unique<Path>();
  *path_ = To<SVGGeometryElement>(GetElement())->AsPath();

  // When the path changes, we need to ensure the stale stroke path cache is
  // cleared. Because this is done in all callsites, we can just DCHECK that it
  // has been cleared here.
  DCHECK(!stroke_path_cache_);
}

float LayoutSVGShape::DashScaleFactor() const {
  NOT_DESTROYED();
  if (!StyleRef().HasDashArray())
    return 1;
  return To<SVGGeometryElement>(*GetElement()).PathLengthScaleFactor();
}

namespace {

bool HasMiterJoinStyle(const ComputedStyle& style) {
  return style.JoinStyle() == kMiterJoin;
}
bool HasSquareCapStyle(const ComputedStyle& style) {
  return style.CapStyle() == kSquareCap;
}

bool CanUseSimpleStrokeApproximation(
    LayoutSVGShape::GeometryType geometry_type) {
  return geometry_type == LayoutSVGShape::GeometryType::kRectangle ||
         geometry_type == LayoutSVGShape::GeometryType::kRoundedRectangle ||
         geometry_type == LayoutSVGShape::GeometryType::kEllipse ||
         geometry_type == LayoutSVGShape::GeometryType::kCircle;
}

bool CanHaveMiters(LayoutSVGShape::GeometryType geometry_type) {
  DCHECK(!CanUseSimpleStrokeApproximation(geometry_type));
  return geometry_type == LayoutSVGShape::GeometryType::kPath;
}

bool CanHaveMitersOrCaps(LayoutSVGShape::GeometryType geometry_type) {
  return geometry_type == LayoutSVGShape::GeometryType::kPath ||
         geometry_type == LayoutSVGShape::GeometryType::kLine;
}

}  // namespace

gfx::RectF LayoutSVGShape::ApproximateStrokeBoundingBox(
    const gfx::RectF& shape_bounds) const {
  NOT_DESTROYED();
  gfx::RectF stroke_box = shape_bounds;

  // Implementation of
  // https://drafts.fxtf.org/css-masking/#compute-stroke-bounding-box
  // except that we ignore whether the stroke is none.

  const float stroke_width = StrokeWidth();
  if (stroke_width <= 0)
    return stroke_box;

  float delta = stroke_width / 2;
  if (CanHaveMitersOrCaps(geometry_type_)) {
    const ComputedStyle& style = StyleRef();
    if (CanHaveMiters(geometry_type_) && HasMiterJoinStyle(style)) {
      const float miter = style.StrokeMiterLimit();
      if (miter < M_SQRT2 && HasSquareCapStyle(style))
        delta *= M_SQRT2;
      else
        delta *= std::max(miter, 1.0f);
    } else if (HasSquareCapStyle(style)) {
      delta *= M_SQRT2;
    }
  }
  stroke_box.Outset(delta);
  return stroke_box;
}

gfx::RectF LayoutSVGShape::HitTestStrokeBoundingBox() const {
  NOT_DESTROYED();
  if (StyleRef().HasStroke())
    return decorated_bounding_box_;
  return ApproximateStrokeBoundingBox(fill_bounding_box_);
}

gfx::RectF LayoutSVGShape::StrokeBoundingBox() const {
  NOT_DESTROYED();
  if (!StyleRef().HasStroke() || IsShapeEmpty()) {
    return fill_bounding_box_;
  }
  // If no Path object has been created for the shape, assume that it is
  // 'simple' and thus the approximation is accurate.
  if (!HasPath()) {
    DCHECK(CanUseSimpleStrokeApproximation(geometry_type_));
    return ApproximateStrokeBoundingBox(fill_bounding_box_);
  }
  StrokeData stroke_data;
  SVGLayoutSupport::ApplyStrokeStyleToStrokeData(stroke_data, StyleRef(), *this,
                                                 DashScaleFactor());
  // Reset the dash pattern.
  //
  // "...set box to be the union of box and the tightest rectangle in
  // coordinate system space that contains the stroke shape of the element,
  // with the assumption that the element has no dash pattern."
  //
  // (https://www.w3.org/TR/SVG2/coords.html#TermStrokeBoundingBox)
  DashArray dashes;
  stroke_data.SetLineDash(dashes, 0);
  const gfx::RectF stroke_bounds = GetPath().StrokeBoundingRect(stroke_data);
  return gfx::UnionRects(fill_bounding_box_, stroke_bounds);
}

bool LayoutSVGShape::ShapeDependentStrokeContains(
    const HitTestLocation& location) {
  NOT_DESTROYED();
  if (!stroke_path_cache_) {
    const Path* path = path_.get();

    AffineTransform root_transform;
    if (HasNonScalingStroke()) {
      // Un-scale to get back to the root-transform (cheaper than re-computing
      // the root transform from scratch).
      root_transform.Scale(StyleRef().EffectiveZoom())
          .PreConcat(NonScalingStrokeTransform());

      path = &NonScalingStrokePath();
    } else {
      root_transform = ComputeRootTransform();
    }

    StrokeData stroke_data;
    SVGLayoutSupport::ApplyStrokeStyleToStrokeData(stroke_data, StyleRef(),
                                                   *this, DashScaleFactor());

    stroke_path_cache_ =
        std::make_unique<Path>(path->StrokePath(stroke_data, root_transform));
  }
  DCHECK(stroke_path_cache_);

  AffineTransform host_space_transform;
  if (HasNonScalingStroke())
    host_space_transform = NonScalingStrokeTransform();
  TransformedHitTestLocation host_space_location(
      location, host_space_transform,
      TransformedHitTestLocation::kDontComputeInverse);
  DCHECK(host_space_location);
  return host_space_location->Intersects(*stroke_path_cache_, RULE_NONZERO);
}

bool LayoutSVGShape::ShapeDependentFillContains(
    const HitTestLocation& location,
    const WindRule fill_rule) const {
  NOT_DESTROYED();
  return location.Intersects(GetPath(), fill_rule);
}

static bool HasPaintServer(const LayoutObject& object, const SVGPaint& paint) {
  if (paint.HasColor())
    return true;
  if (paint.HasUrl()) {
    SVGResourceClient* client = SVGResources::GetClient(object);
    if (GetSVGResourceAsType<LayoutSVGResourcePaintServer>(*client,
                                                           paint.Resource()))
      return true;
  }
  return false;
}

bool LayoutSVGShape::FillContains(const HitTestLocation& location,
                                  bool requires_fill,
                                  const WindRule fill_rule) {
  NOT_DESTROYED();
  if (!location.Intersects(fill_bounding_box_)) {
    return false;
  }

  if (requires_fill && !HasPaintServer(*this, StyleRef().FillPaint()))
    return false;

  return ShapeDependentFillContains(location, fill_rule);
}

bool LayoutSVGShape::StrokeContains(const HitTestLocation& location,
                                    bool requires_stroke) {
  NOT_DESTROYED();
  // "A zero value causes no stroke to be painted."
  if (StyleRef().StrokeWidth().IsZero())
    return false;

  if (requires_stroke) {
    if (!location.Intersects(DecoratedBoundingBox())) {
      return false;
    }

    if (!HasPaintServer(*this, StyleRef().StrokePaint()))
      return false;
  } else if (!location.Intersects(HitTestStrokeBoundingBox())) {
    return false;
  }
  return ShapeDependentStrokeContains(location);
}

SVGLayoutResult LayoutSVGShape::UpdateSVGLayout(
    const SVGLayoutInfo& layout_info) {
  NOT_DESTROYED();

  // The cached stroke may be affected by the ancestor transform, and so needs
  // to be cleared regardless of whether the shape or bounds have changed.
  stroke_path_cache_.reset();

  // Update the object bounds of the shape.
  bool bbox_changed = false;
  if (needs_shape_update_) {
    gfx::RectF new_object_bounding_box = UpdateShapeFromElement();
    ClampBoundsToFinite(new_object_bounding_box);
    bbox_changed = fill_bounding_box_ != new_object_bounding_box;
    fill_bounding_box_ = new_object_bounding_box;
    needs_shape_update_ = false;
    needs_boundaries_update_ = true;
  }

  SVGLayoutResult result;
  if (UpdateAfterSVGLayout(layout_info, bbox_changed)) {
    result.bounds_changed = true;
  }

  if (needs_boundaries_update_) {
    if (!IsShapeEmpty()) {
      decorated_bounding_box_ = CalculateStrokeBoundingBox();
      UpdateMarkerBounds();
    } else {
      decorated_bounding_box_ = fill_bounding_box_;
    }
    needs_boundaries_update_ = false;
    result.bounds_changed = true;
  }

  DCHECK(!needs_shape_update_);
  DCHECK(!needs_boundaries_update_);
  DCHECK(!needs_transform_update_);
  ClearNeedsLayout();
  return result;
}

bool LayoutSVGShape::UpdateAfterSVGLayout(const SVGLayoutInfo& layout_info,
                                          bool bbox_changed) {
  if (bbox_changed) {
    SetShouldDoFullPaintInvalidation();

    // Invalidate all resources of this client if our reference box changed.
    if (EverHadLayout()) {
      SVGResourceInvalidator resource_invalidator(*this);
      resource_invalidator.InvalidateEffects();
      resource_invalidator.InvalidatePaints();
    }
  }
  if (!needs_transform_update_ && transform_uses_reference_box_) {
    needs_transform_update_ =
        CheckForImplicitTransformChange(layout_info, bbox_changed);
    if (needs_transform_update_)
      SetNeedsPaintPropertyUpdate();
  }
  bool updated_transform = false;
  if (needs_transform_update_) {
    local_transform_ =
        TransformHelper::ComputeTransformIncludingMotion(*GetElement());
    needs_transform_update_ = false;
    updated_transform = true;
  }
  // The non-scaling-stroke transform depends on the local transform,
  // which in turn may depend on the object bounding box, thus we
  // can't update the non-scaling-stroke data before any of those have
  // been computed.
  //
  // We always do this because the non-scaling-stroke transform
  // depends on ancestor transforms. For the same reason we'll also
  // need to update the (stroke) bounds as a result.
  if (HasNonScalingStroke() && !IsShapeEmpty()) {
    UpdateNonScalingStrokeData();
    needs_boundaries_update_ = true;
    return true;
  }
  return updated_transform;
}

AffineTransform LayoutSVGShape::ComputeRootTransform() const {
  NOT_DESTROYED();
  const LayoutObject* root = this;
  while (root && !root->IsSVGRoot())
    root = root->Parent();
  return AffineTransform::FromTransform(
      LocalToAncestorTransform(To<LayoutSVGRoot>(root)));
}

AffineTransform LayoutSVGShape::ComputeNonScalingStrokeTransform() const {
  NOT_DESTROYED();
  // Compute the CTM to the SVG root. This should probably be the CTM all the
  // way to the "canvas" of the page ("host" coordinate system), but with our
  // current approach of applying/painting non-scaling-stroke, that can break in
  // unpleasant ways (see crbug.com/747708 for an example.) Maybe it would be
  // better to apply this effect during rasterization?
  AffineTransform host_transform;
  host_transform.Scale(1 / StyleRef().EffectiveZoom())
      .PreConcat(ComputeRootTransform());

  // Width of non-scaling stroke is independent of translation, so zero it out
  // here.
  host_transform.SetE(0);
  host_transform.SetF(0);
  return host_transform;
}

void LayoutSVGShape::UpdateNonScalingStrokeData() {
  NOT_DESTROYED();
  DCHECK(HasNonScalingStroke());

  const AffineTransform transform = ComputeNonScalingStrokeTransform();
  auto& rare_data = EnsureRareData();
  if (rare_data.non_scaling_stroke_transform_ != transform) {
    SetShouldDoFullPaintInvalidation();
    rare_data.non_scaling_stroke_transform_ = transform;
  }

  // For non-scaling-stroke we need to have a Path representation, so
  // create one here if needed.
  rare_data.non_scaling_stroke_path_ = EnsurePath();
  rare_data.non_scaling_stroke_path_.Transform(transform);
}

void LayoutSVGShape::Paint(const PaintInfo& paint_info) const {
  NOT_DESTROYED();
  SVGShapePainter(*this).Paint(paint_info);
}

bool LayoutSVGShape::NodeAtPoint(HitTestResult& result,
                                 const HitTestLocation& hit_test_location,
                                 const PhysicalOffset& accumulated_offset,
                                 HitTestPhase phase) {
  NOT_DESTROYED();
  DCHECK_EQ(accumulated_offset, PhysicalOffset());
  // We only draw in the foreground phase, so we only hit-test then.
  if (phase != HitTestPhase::kForeground)
    return false;
  if (IsShapeEmpty())
    return false;
  const ComputedStyle& style = StyleRef();
  const PointerEventsHitRules hit_rules(
      PointerEventsHitRules::kSvgGeometryHitTesting, result.GetHitTestRequest(),
      style.UsedPointerEvents());
  if (hit_rules.require_visible &&
      style.Visibility() != EVisibility::kVisible) {
    return false;
  }

  TransformedHitTestLocation local_location(hit_test_location,
                                            LocalToSVGParentTransform());
  if (!local_location)
    return false;
  if (HasClipPath() && !ClipPathClipper::HitTest(*this, *local_location)) {
    return false;
  }

  if (HitTestShape(result.GetHitTestRequest(), *local_location, hit_rules)) {
    UpdateHitTestResult(result, PhysicalOffset::FromPointFRound(
                                    local_location->TransformedPoint()));
    if (result.AddNodeToListBasedTestResult(GetElement(), *local_location) ==
        kStopHitTesting)
      return true;
  }

  return false;
}

bool LayoutSVGShape::HitTestShape(const HitTestRequest& request,
                                  const HitTestLocation& local_location,
                                  PointerEventsHitRules hit_rules) {
  NOT_DESTROYED();
  if (hit_rules.can_hit_bounding_box &&
      local_location.Intersects(ObjectBoundingBox()))
    return true;

  // TODO(chrishtr): support rect-based intersections in the cases below.
  const ComputedStyle& style = StyleRef();
  if (hit_rules.can_hit_stroke &&
      (style.HasStroke() || !hit_rules.require_stroke) &&
      StrokeContains(local_location, hit_rules.require_stroke))
    return true;
  WindRule fill_rule = style.FillRule();
  if (request.SvgClipContent())
    fill_rule = style.ClipRule();
  if (hit_rules.can_hit_fill && (style.HasFill() || !hit_rules.require_fill) &&
      FillContains(local_location, hit_rules.require_fill, fill_rule))
    return true;
  return false;
}

gfx::RectF LayoutSVGShape::CalculateStrokeBoundingBox() const {
  NOT_DESTROYED();
  if (!StyleRef().HasStroke()) {
    return fill_bounding_box_;
  }
  if (HasNonScalingStroke())
    return CalculateNonScalingStrokeBoundingBox();
  return ApproximateStrokeBoundingBox(fill_bounding_box_);
}

gfx::RectF LayoutSVGShape::CalculateNonScalingStrokeBoundingBox() const {
  NOT_DESTROYED();
  DCHECK(path_);
  DCHECK(StyleRef().HasStroke());
  DCHECK(HasNonScalingStroke());

  gfx::RectF stroke_bounding_box = fill_bounding_box_;
  const auto& non_scaling_transform = NonScalingStrokeTransform();
  if (non_scaling_transform.IsInvertible()) {
    gfx::RectF stroke_bounding_rect =
        ApproximateStrokeBoundingBox(NonScalingStrokePath().BoundingRect());
    stroke_bounding_rect =
        non_scaling_transform.Inverse().MapRect(stroke_bounding_rect);
    stroke_bounding_box.Union(stroke_bounding_rect);
  }
  return stroke_bounding_box;
}

float LayoutSVGShape::StrokeWidth() const {
  NOT_DESTROYED();
  const SVGViewportResolver viewport_resolver(*this);
  return ValueForLength(StyleRef().StrokeWidth(), viewport_resolver);
}

float LayoutSVGShape::StrokeWidthForMarkerUnits() const {
  NOT_DESTROYED();
  float stroke_width = StrokeWidth();
  if (HasNonScalingStroke()) {
    const auto& non_scaling_transform = NonScalingStrokeTransform();
    if (!non_scaling_transform.IsInvertible())
      return 0;
    float scale_factor =
        ClampTo<float>(sqrt((non_scaling_transform.XScaleSquared() +
                             non_scaling_transform.YScaleSquared()) /
                            2));
    stroke_width /= scale_factor;
  }
  return stroke_width;
}

LayoutSVGShapeRareData& LayoutSVGShape::EnsureRareData() const {
  NOT_DESTROYED();
  if (!rare_data_)
    rare_data_ = std::make_unique<LayoutSVGShapeRareData>();
  return *rare_data_.get();
}

RasterEffectOutset LayoutSVGShape::VisualRectOutsetForRasterEffects() const {
  NOT_DESTROYED();
  // Account for raster expansions due to SVG stroke hairline raster effects.
  const ComputedStyle& style = StyleRef();
  if (style.HasVisibleStroke()) {
    if (style.CapStyle() != kButtCap)
      return RasterEffectOutset::kWholePixel;
    return RasterEffectOutset::kHalfPixel;
  }
  return RasterEffectOutset::kNone;
}

}  // namespace blink

"""

```