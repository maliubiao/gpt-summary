Response:
Let's break down the thought process for analyzing the given C++ code.

1. **Understand the Goal:** The request asks for the functionality of the `svg_resources.cc` file, its relationship to web technologies (JavaScript, HTML, CSS), illustrative examples, logical inferences (with inputs and outputs), and common usage errors.

2. **Initial Skim and Identify Key Structures:** Quickly read through the code, paying attention to:
    * Included headers: These hint at the file's dependencies and the types of operations it performs (e.g., `layout_svg_resource_filter.h`, `computed_style.h`, `svg_filter_builder.h`).
    * Namespace: `blink` indicates this is part of the Chromium rendering engine.
    * Class names: `SVGResources`, `SVGElementResourceClient`, `SVGResourceInvalidator`. These are the main actors.
    * Method names:  `GetClient`, `EnsureClient`, `UpdateEffects`, `ClearEffects`, `UpdatePaints`, `ClearPaints`, `UpdateMarkers`, `ClearMarkers`, `ResourceContentChanged`, `FilterPrimitiveChanged`, `UpdateFilterData`, `InvalidateFilterData`, etc. These reveal the actions the file performs.

3. **Focus on `SVGResources` Class:** This appears to be the central hub. Analyze its methods:
    * `GetClient`, `EnsureClient`:  Handle associating an `SVGElement` with an `SVGElementResourceClient`. This suggests managing data related to specific SVG elements.
    * `ReferenceBoxForEffects`: Calculates a bounding box for effects like filters. The different `GeometryBox` enum values (`kPaddingBox`, `kContentBox`, etc.) and the handling of `foreignObject` suggest it's dealing with how effects are spatially applied.
    * `UpdateEffects`, `ClearEffects`: These methods manage the application and removal of visual effects (clip paths and filters) based on CSS styles. The interaction with `ComputedStyle` and `ReferenceClipPathOperation` is important.
    * `UpdatePaints`, `ClearPaints`: Manage the application and removal of paint servers (fills and strokes) defined in CSS. The interaction with `StyleSVGResource` is key.
    * `UpdateMarkers`, `ClearMarkers`: Similar to paints, but for SVG markers.

4. **Focus on `SVGElementResourceClient` Class:** This seems to hold per-element data related to SVG resources.
    * Constructor: Takes an `SVGElement*`.
    * `FilterData` (inner class):  Manages data specific to SVG filters, including building and invalidating the filter graph. This is a significant part of the functionality.
    * `ResourceContentChanged`:  Handles notifications when a referenced SVG resource changes. It invalidates relevant caches and triggers repaints or layouts. This connects directly to the dynamic nature of SVG and how changes propagate.
    * `FilterPrimitiveChanged`:  Handles changes to individual filter primitives within a `<filter>` element. It allows for more targeted invalidation, which is an optimization.
    * `UpdateFilterData`: Builds or updates the filter data for compositing based on the current style.
    * `InvalidateFilterData`:  Flags the filter data as needing a rebuild.

5. **Focus on `SVGResourceInvalidator` Class:** This provides a higher-level interface for invalidating resources.
    * `InvalidateEffects`: Invalidates filters, clip paths, and masks.
    * `InvalidatePaints`: Invalidates fill and stroke paint servers.

6. **Connect to Web Technologies:** Now, relate the identified functionality to HTML, CSS, and JavaScript:
    * **HTML:** The code deals with SVG elements (`<svg>`, `<filter>`, `<clipPath>`, paint server elements like `<linearGradient>`, `<radialGradient>`, `<pattern>`, and elements that can be styled like `<rect>`, `<circle>`, `<path>`, `<text>`). The handling of `<foreignObject>` is a direct link to embedding non-SVG content.
    * **CSS:**  The code heavily relies on `ComputedStyle`. Properties like `clip-path`, `filter`, `fill`, `stroke`, `marker-start`, `marker-mid`, `marker-end` directly trigger the logic in this file. The examples should demonstrate how changes to these CSS properties cause the code to execute.
    * **JavaScript:** While the C++ code itself doesn't directly interact with JavaScript, JavaScript manipulation of the DOM and CSSOM will indirectly trigger the functionality in this file. For instance, using JavaScript to change the `filter` property of an SVG element will lead to `UpdateEffects` being called.

7. **Logical Inferences (Inputs and Outputs):**  Choose specific methods and illustrate their behavior with concrete examples. Think about:
    * **`ReferenceBoxForEffects`:**  Input: a layout object and a `GeometryBox` value. Output: a `gfx::RectF`.
    * **`UpdateEffects`:** Input: a layout object and style differences. Output: Potentially updates internal state (client data) and triggers repaints.
    * **`ResourceContentChanged`:** Input: an `SVGResource`. Output: Triggers various invalidations (paint, layout, filter data) depending on the resource type.

8. **Common Usage Errors:** Think about mistakes developers might make when working with SVG and CSS that this code helps to prevent or handle:
    * Incorrectly referencing filter IDs.
    * Not understanding how `objectBoundingBox` works with transformations.
    * Modifying SVG resources without triggering updates.

9. **Structure the Answer:** Organize the findings into clear sections: Functionality, Relationship to Web Technologies, Logical Inferences, Common Usage Errors. Use bullet points and clear language. Provide code snippets for examples where appropriate.

10. **Review and Refine:**  Read through the generated answer to ensure accuracy, clarity, and completeness. Check for any logical inconsistencies or missing information. Make sure the examples are illustrative and easy to understand. Ensure the language is precise and avoids jargon where possible. For example, instead of just saying "it manages filters," explain *how* it manages them (building, invalidating, etc.). Make sure the connection to HTML, CSS, and JavaScript is explicit.
这个文件 `blink/renderer/core/layout/svg/svg_resources.cc` 在 Chromium 的 Blink 渲染引擎中扮演着管理和维护 SVG 资源及其与布局对象之间关系的关键角色。 它的主要功能是**追踪和更新 SVG 元素使用的各种资源（如滤镜、裁剪路径、渐变、图案、标记等），并在这些资源发生变化时通知相关的布局对象，以便触发必要的重绘或重排。**

以下是它的详细功能点：

**核心功能：**

1. **管理 SVG 元素和其资源客户端 (SVGElementResourceClient):**
   - 为每个需要追踪资源的 SVG 元素创建一个 `SVGElementResourceClient` 对象。
   - `GetClient(const LayoutObject& object)`:  获取给定布局对象对应的 `SVGElementResourceClient`。
   - `EnsureClient(const LayoutObject& object)`: 获取或创建给定布局对象对应的 `SVGElementResourceClient`。

2. **计算效果的参考框 (ReferenceBoxForEffects):**
   - 确定用于应用 SVG 效果（如滤镜、裁剪路径）的参考坐标系和边界。
   - 考虑不同的 `geometry_box` 属性值（`objectBoundingBox`, `userSpaceOnUse` 等对应的 PaddingBox, ContentBox, FillBox, MarginBox, BorderBox, StrokeBox, ViewBox）。
   - 特殊处理 `<foreignObject>` 元素，确保其参考框的计算正确。
   - **假设输入：** 一个 `<rect>` 元素的布局对象， `geometry_box` 为 `GeometryBox::kObjectBoundingBox`。
   - **输出：** 该 `<rect>` 元素的边界框 `gfx::RectF`。

3. **更新和清理 SVG 效果 (UpdateEffects, ClearEffects):**
   - 当 SVG 元素的 `filter` 或 `clip-path` CSS 属性发生变化时，更新其 `SVGElementResourceClient` 所追踪的资源。
   - `UpdateEffects`:
     - 添加新的滤镜或裁剪路径的客户端。
     - 移除旧的滤镜或裁剪路径的客户端。
     - 在滤镜发生变化时，标记需要更新滤镜数据。
   - `ClearEffects`:
     - 当布局对象被销毁时，清理其追踪的滤镜和裁剪路径资源，防止内存泄漏。

4. **更新和清理 SVG 填充和描边 (UpdatePaints, ClearPaints):**
   - 当 SVG 元素的 `fill` 或 `stroke` CSS 属性引用了 SVG 资源（如渐变、图案）时，更新其 `SVGElementResourceClient` 所追踪的资源。
   - `UpdatePaints`: 添加新的填充或描边资源的客户端。
   - `ClearPaints`: 移除旧的填充或描边资源的客户端。

5. **更新和清理 SVG 标记 (UpdateMarkers, ClearMarkers):**
   - 当 SVG 元素的 `marker-start`, `marker-mid`, `marker-end` CSS 属性引用了 SVG 资源（如 `<marker>` 元素）时，更新其 `SVGElementResourceClient` 所追踪的资源。
   - `UpdateMarkers`: 添加新的标记资源的客户端。
   - `ClearMarkers`: 移除旧的标记资源的客户端。

6. **处理资源内容变化 (ResourceContentChanged):**
   - 当一个被引用的 SVG 资源（例如，一个 `<filter>` 或 `<linearGradient>` 元素）的内容发生变化时，通知所有使用了该资源的 `SVGElementResourceClient`。
   - 根据资源类型和影响范围，触发布局对象的完全重绘、子树重绘或属性更新。
   - **假设输入：**  一个 `<linearGradient>` 元素的内容被 JavaScript 修改。
   - **输出：** 所有使用了该 `<linearGradient>` 作为 `fill` 或 `stroke` 的 SVG 元素都将被标记为需要重绘。

7. **处理滤镜图元变化 (FilterPrimitiveChanged):**
   - 当 `<filter>` 元素内部的滤镜图元（例如 `<feGaussianBlur>`) 的属性发生变化时，执行更精细的更新。
   - 如果可能，只重新构建受影响的滤镜链部分，提高性能。
   - **假设输入：**  一个 `<feGaussianBlur>` 元素的 `stdDeviation` 属性被 JavaScript 修改。
   - **输出：**  使用了包含该 `<feGaussianBlur>` 的 `<filter>` 元素的 SVG 元素将被标记为需要更新其滤镜效果并可能需要重绘。

8. **管理滤镜数据 (FilterData):**
   - `SVGElementResourceClient::FilterData` 是一个内部类，用于缓存和管理 SVG 滤镜效果的构建结果。
   - `BuildPaintFilter()`: 根据滤镜效果构建 Skia 的 `PaintFilter` 对象，用于 GPU 加速渲染。
   - `Invalidate()`:  当滤镜图元的属性改变时，执行更细粒度的失效操作，尝试只重新构建受影响的部分。
   - `UpdateFilterData()`:  根据当前样式构建或更新元素的滤镜数据。
   - `InvalidateFilterData()`:  标记元素的滤镜数据为失效，需要在下次绘制时重新构建。

9. **SVG 资源失效器 (SVGResourceInvalidator):**
   - 提供一个更方便的接口来批量失效与特定布局对象相关的 SVG 资源。
   - `InvalidateEffects()`: 失效滤镜、裁剪路径和遮罩。
   - `InvalidatePaints()`: 失效填充和描边。

**与 JavaScript, HTML, CSS 的关系：**

- **HTML:**  这个文件处理的是渲染 HTML 中 `<svg>` 元素及其子元素。它负责将 SVG 结构和样式转化为屏幕上的像素。
  - **举例：** 当 HTML 中定义了一个 `<rect>` 元素，并应用了 `filter: url(#myBlur)`，这个文件会负责找到 ID 为 `myBlur` 的 `<filter>` 元素，并将其应用于 `<rect>` 的渲染过程中。

- **CSS:**  CSS 属性是触发这个文件中逻辑的关键。
  - **`filter`:**  当 SVG 元素的 `filter` 属性被设置或修改时，`UpdateEffects` 函数会被调用，负责解析滤镜的 URL，找到对应的 `<filter>` 元素，并构建用于渲染的滤镜效果。
  - **`clip-path`:**  类似于 `filter`，`UpdateEffects` 会处理裁剪路径的引用和更新。
  - **`fill`, `stroke`:** 当这些属性引用了 SVG 资源（例如 `fill: url(#myGradient)`) 时，`UpdatePaints` 会追踪这些资源。
  - **`marker-start`, `marker-mid`, `marker-end`:**  控制 SVG 路径的标记，`UpdateMarkers` 负责追踪相关的 `<marker>` 元素。
  - **举例：**  在 CSS 中设置 `.my-shape { fill: red; }` 会导致这个文件中的逻辑被触发，确定如何用红色填充该形状。如果设置为 `fill: url(#myGradient);`，则会追踪 `myGradient` 资源。

- **JavaScript:** JavaScript 可以通过 DOM API 修改 HTML 结构和 CSS 样式，从而间接地触发 `svg_resources.cc` 中的逻辑。
  - **举例：** 使用 JavaScript 修改一个 `<filter>` 元素的内部结构（例如，更改 `<feGaussianBlur>` 的 `stdDeviation` 属性）会触发 `FilterPrimitiveChanged` 函数，导致使用了该滤镜的元素重新渲染。
  - **举例：**  使用 JavaScript 动态地添加或删除带有 `filter` 属性的 SVG 元素，会触发 `UpdateEffects` 和 `ClearEffects`，管理资源的生命周期。

**逻辑推理的假设输入与输出：**

**场景：** 一个 `<circle>` 元素使用了 `filter: url(#dropShadow)`，并且 `dropShadow` 滤镜的内容被修改。

- **假设输入：**
    1. 一个 `<circle>` 元素的布局对象。
    2. 该 `<circle>` 元素的 `filter` 属性值为 `url(#dropShadow)`。
    3. 名为 `dropShadow` 的 `<filter>` 元素内部的某个滤镜图元的属性值发生了改变。
- **输出：**
    1. `FilterPrimitiveChanged` 函数被调用。
    2. `SVGElementResourceClient` 中的 `FilterData` 对象被标记为失效或部分更新。
    3. 该 `<circle>` 元素被标记为需要进行属性更新 (`SetNeedsPaintPropertyUpdate`)，以便在下次绘制时重新应用新的滤镜效果。
    4. 如果修改影响了布局，可能还会触发布局更新。

**常见的使用错误举例：**

1. **忘记在 JavaScript 修改 SVG 资源后触发更新:** 如果直接通过 DOM API 修改了 `<filter>` 或 `<linearGradient>` 等元素的内容，但没有触发任何导致样式重新计算或布局更新的操作，那么渲染结果可能不会立即反映这些更改。
   - **例子：**
     ```javascript
     const blur = document.getElementById('myBlur');
     blur.querySelector('feGaussianBlur').setAttribute('stdDeviation', 10);
     // 此时，屏幕上的模糊效果可能没有立即更新，需要触发重绘。
     ```
   - **正确做法：**  修改后通常会导致浏览器的渲染引擎自动检测到变化并触发更新，但某些复杂的场景下可能需要手动触发，例如通过修改元素的某个 CSS 属性或强制布局。

2. **错误地理解 `objectBoundingBox` 单位:**  在使用滤镜或裁剪路径时，如果单位设置为 `objectBoundingBox`，那么坐标是相对于应用该效果的元素的边界框的。 如果不理解这一点，可能会导致效果的位置或大小不符合预期，尤其是在元素进行了变换 (transform) 的情况下。
   - **例子：**  一个滤镜使用了 `filterUnits="objectBoundingBox"`，其中的坐标和尺寸应该在 0 到 1 之间，表示元素边界框的比例。如果直接使用像素值，效果可能不会正确缩放。

3. **在动态创建和删除 SVG 元素时没有考虑资源清理:**  如果在 JavaScript 中动态创建并移除了引用了 SVG 资源的元素，而没有正确地管理这些资源，可能会导致内存泄漏。 `svg_resources.cc` 负责在布局对象销毁时清理资源，但如果布局对象没有被正确地清理，资源也可能无法释放。

总而言之，`blink/renderer/core/layout/svg/svg_resources.cc` 是 Blink 渲染引擎中处理 SVG 资源管理的核心组件，它连接了 SVG 元素、CSS 样式和实际的渲染过程，确保了 SVG 内容能够正确、高效地显示在网页上，并且能够响应动态的修改。

### 提示词
```
这是目录为blink/renderer/core/layout/svg/svg_resources.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) Research In Motion Limited 2010. All rights reserved.
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

#include "third_party/blink/renderer/core/layout/svg/svg_resources.h"

#include "base/ranges/algorithm.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_resource_filter.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_resource_paint_server.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_text.h"
#include "third_party/blink/renderer/core/paint/filter_effect_builder.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/style/reference_clip_path_operation.h"
#include "third_party/blink/renderer/core/style/style_svg_resource.h"
#include "third_party/blink/renderer/core/svg/graphics/filters/svg_filter_builder.h"
#include "third_party/blink/renderer/core/svg/svg_filter_primitive_standard_attributes.h"
#include "third_party/blink/renderer/core/svg/svg_length_functions.h"
#include "third_party/blink/renderer/core/svg/svg_resource.h"
#include "third_party/blink/renderer/platform/graphics/filters/filter.h"
#include "third_party/blink/renderer/platform/graphics/filters/filter_effect.h"
#include "third_party/blink/renderer/platform/graphics/filters/paint_filter_builder.h"
#include "third_party/blink/renderer/platform/graphics/filters/source_graphic.h"

namespace blink {

SVGElementResourceClient* SVGResources::GetClient(const LayoutObject& object) {
  return To<SVGElement>(object.GetNode())->GetSVGResourceClient();
}

SVGElementResourceClient& SVGResources::EnsureClient(
    const LayoutObject& object) {
  return To<SVGElement>(object.GetNode())->EnsureSVGResourceClient();
}

gfx::RectF SVGResources::ReferenceBoxForEffects(
    const LayoutObject& layout_object,
    GeometryBox geometry_box,
    ForeignObjectQuirk foreign_object_quirk) {
  // Text "sub-elements" (<tspan>, <textpath>, <a>) should use the entire
  // <text>s object bounding box rather then their own.
  // https://svgwg.org/svg2-draft/text.html#ObjectBoundingBoxUnitsTextObjects
  const LayoutObject* obb_layout_object = &layout_object;
  if (layout_object.IsSVGInline()) {
    obb_layout_object =
        LayoutSVGText::LocateLayoutSVGTextAncestor(&layout_object);
  }
  DCHECK(obb_layout_object);

  gfx::RectF box;
  switch (geometry_box) {
    case GeometryBox::kPaddingBox:
    case GeometryBox::kContentBox:
    case GeometryBox::kFillBox:
      box = obb_layout_object->ObjectBoundingBox();
      break;
    case GeometryBox::kMarginBox:
    case GeometryBox::kBorderBox:
    case GeometryBox::kStrokeBox:
      box = obb_layout_object->StrokeBoundingBox();
      break;
    case GeometryBox::kViewBox: {
      const SVGViewportResolver viewport_resolver(obb_layout_object);
      box.set_size(viewport_resolver.ResolveViewport());
      break;
    }
    default:
      NOTREACHED();
  }

  if (foreign_object_quirk == ForeignObjectQuirk::kEnabled &&
      obb_layout_object->IsSVGForeignObject()) {
    // For SVG foreign objects, remove the position part of the bounding box.
    // The position is already baked into the transform, and we don't want to
    // re-apply the offset when, e.g., using "objectBoundingBox" for
    // clipPathUnits. Similarly, the reference box should have zoom applied.
    // This simple approach only works because foreign objects do not support
    // strokes.
    box.set_origin(gfx::PointF());
    box.Scale(obb_layout_object->StyleRef().EffectiveZoom());
  }

  return box;
}

void SVGResources::UpdateEffects(LayoutObject& object,
                                 StyleDifference diff,
                                 const ComputedStyle* old_style) {
  const bool had_client = GetClient(object);
  const ComputedStyle& style = object.StyleRef();
  if (auto* reference_clip =
          DynamicTo<ReferenceClipPathOperation>(style.ClipPath())) {
    reference_clip->AddClient(EnsureClient(object));
  }
  if (style.HasFilter())
    style.Filter().AddClient(EnsureClient(object));
  // FilterChanged() includes changes from more than just the 'filter'
  // property, so explicitly check that a filter existed or exists.
  if (diff.FilterChanged() &&
      (style.HasFilter() || (old_style && old_style->HasFilter()))) {
    // We either created one above, or had one already.
    DCHECK(GetClient(object));
    if (RuntimeEnabledFeatures::SvgTransformOptimizationEnabled()) {
      GetClient(object)->InvalidateFilterData();
    } else {
      object.SetNeedsPaintPropertyUpdate();
      GetClient(object)->MarkFilterDataDirty();
    }
  }
  if (!old_style || !had_client)
    return;
  SVGElementResourceClient* client = GetClient(object);
  if (auto* old_reference_clip =
          DynamicTo<ReferenceClipPathOperation>(old_style->ClipPath())) {
    old_reference_clip->RemoveClient(*client);
  }
  if (old_style->HasFilter())
    old_style->Filter().RemoveClient(*client);
}

void SVGResources::ClearEffects(const LayoutObject& object) {
  const ComputedStyle* style = object.Style();
  if (!style)
    return;
  SVGElementResourceClient* client = GetClient(object);
  if (!client)
    return;
  if (auto* old_reference_clip =
          DynamicTo<ReferenceClipPathOperation>(style->ClipPath())) {
    old_reference_clip->RemoveClient(*client);
  }
  if (style->HasFilter()) {
    style->Filter().RemoveClient(*client);
    // TODO(fs): We need to invalidate filter data here because the resource
    // client is owned by the Element - thus staying alive with it even when
    // the LayoutObject is detached. Move ownership to the LayoutObject.
    client->InvalidateFilterData();
  }
}

void SVGResources::UpdatePaints(const LayoutObject& object,
                                const ComputedStyle* old_style,
                                const ComputedStyle& style) {
  const bool had_client = GetClient(object);
  if (StyleSVGResource* paint_resource = style.FillPaint().Resource())
    paint_resource->AddClient(EnsureClient(object));
  if (StyleSVGResource* paint_resource = style.StrokePaint().Resource())
    paint_resource->AddClient(EnsureClient(object));
  if (had_client)
    ClearPaints(object, old_style);
}

void SVGResources::ClearPaints(const LayoutObject& object,
                               const ComputedStyle* style) {
  if (!style)
    return;
  SVGResourceClient* client = GetClient(object);
  if (!client)
    return;
  if (StyleSVGResource* paint_resource = style->FillPaint().Resource())
    paint_resource->RemoveClient(*client);
  if (StyleSVGResource* paint_resource = style->StrokePaint().Resource())
    paint_resource->RemoveClient(*client);
}

void SVGResources::UpdateMarkers(const LayoutObject& object,
                                 const ComputedStyle* old_style) {
  const bool had_client = GetClient(object);
  const ComputedStyle& style = object.StyleRef();
  if (StyleSVGResource* marker_resource = style.MarkerStartResource())
    marker_resource->AddClient(EnsureClient(object));
  if (StyleSVGResource* marker_resource = style.MarkerMidResource())
    marker_resource->AddClient(EnsureClient(object));
  if (StyleSVGResource* marker_resource = style.MarkerEndResource())
    marker_resource->AddClient(EnsureClient(object));
  if (had_client)
    ClearMarkers(object, old_style);
}

void SVGResources::ClearMarkers(const LayoutObject& object,
                                const ComputedStyle* style) {
  if (!style)
    return;
  SVGResourceClient* client = GetClient(object);
  if (!client)
    return;
  if (StyleSVGResource* marker_resource = style->MarkerStartResource())
    marker_resource->RemoveClient(*client);
  if (StyleSVGResource* marker_resource = style->MarkerMidResource())
    marker_resource->RemoveClient(*client);
  if (StyleSVGResource* marker_resource = style->MarkerEndResource())
    marker_resource->RemoveClient(*client);
}

class SVGElementResourceClient::FilterData final
    : public GarbageCollected<SVGElementResourceClient::FilterData> {
 public:
  FilterData(FilterEffect* last_effect, SVGFilterGraphNodeMap* node_map)
      : last_effect_(last_effect), node_map_(node_map) {}

  bool HasEffects() const { return last_effect_ != nullptr; }
  sk_sp<PaintFilter> BuildPaintFilter() {
    return paint_filter_builder::Build(last_effect_.Get(),
                                       kInterpolationSpaceSRGB);
  }

  // Perform a finegrained invalidation of the filter chain for the
  // specified filter primitive and attribute. Returns false if no
  // further invalidation is required, otherwise true.
  bool Invalidate(SVGFilterPrimitiveStandardAttributes& primitive,
                  const QualifiedName& attribute) {
    if (FilterEffect* effect = node_map_->EffectForElement(primitive)) {
      if (!primitive.SetFilterEffectAttribute(effect, attribute))
        return false;  // No change
      node_map_->InvalidateDependentEffects(effect);
    }
    return true;
  }

  void Dispose() {
    node_map_ = nullptr;
    if (last_effect_)
      last_effect_->DisposeImageFiltersRecursive();
    last_effect_ = nullptr;
  }

  void Trace(Visitor* visitor) const {
    visitor->Trace(last_effect_);
    visitor->Trace(node_map_);
  }

 private:
  Member<FilterEffect> last_effect_;
  Member<SVGFilterGraphNodeMap> node_map_;
};

SVGElementResourceClient::SVGElementResourceClient(SVGElement* element)
    : element_(element), filter_data_dirty_(false) {}

namespace {

template <typename ContainerType>
bool ContainsResource(const ContainerType* container, SVGResource* resource) {
  return container && container->Resource() == resource;
}

bool ContainsResource(const FilterOperations& operations,
                      SVGResource* resource) {
  return base::ranges::any_of(
      operations.Operations(), [resource](const FilterOperation* operation) {
        return ContainsResource(DynamicTo<ReferenceFilterOperation>(operation),
                                resource);
      });
}

}  // namespace

void SVGElementResourceClient::ResourceContentChanged(SVGResource* resource) {
  LayoutObject* layout_object = element_->GetLayoutObject();
  if (!layout_object)
    return;

  const ComputedStyle& style = layout_object->StyleRef();
  if (style.HasFilter() && ContainsResource(style.Filter(), resource)) {
    InvalidateFilterData();
    layout_object->SetShouldDoFullPaintInvalidation();
  }

  if (auto* container = DynamicTo<LayoutSVGResourceContainer>(layout_object)) {
    container->RemoveAllClientsFromCache();
    return;
  }

  if (ContainsResource(style.FillPaint().Resource(), resource) ||
      ContainsResource(style.StrokePaint().Resource(), resource)) {
    // Since LayoutSVGInlineTexts don't have SVGResources (they use their
    // parent's), they will not be notified of changes to paint servers. So
    // if the client is one that could have a LayoutSVGInlineText use a
    // paint invalidation reason that will force paint invalidation of the
    // entire <text>/<tspan>/... subtree.
    layout_object->SetSubtreeShouldDoFullPaintInvalidation(
        PaintInvalidationReason::kSVGResource);
  }

  bool needs_layout = false;
  if (ContainsResource(style.MarkerStartResource(), resource) ||
      ContainsResource(style.MarkerMidResource(), resource) ||
      ContainsResource(style.MarkerEndResource(), resource)) {
    needs_layout = true;
    layout_object->SetNeedsBoundariesUpdate();
  }

  const auto* clip_reference =
      DynamicTo<ReferenceClipPathOperation>(style.ClipPath());
  if (ContainsResource(clip_reference, resource)) {
    // TODO(fs): "Downgrade" to non-subtree?
    layout_object->SetSubtreeShouldDoFullPaintInvalidation();
    layout_object->SetNeedsPaintPropertyUpdate();
  }

  LayoutSVGResourceContainer::MarkForLayoutAndParentResourceInvalidation(
      *layout_object, needs_layout);
}

void SVGElementResourceClient::FilterPrimitiveChanged(
    SVGResource* resource,
    SVGFilterPrimitiveStandardAttributes& primitive,
    const QualifiedName& attribute) {
  if (filter_data_ && !filter_data_->Invalidate(primitive, attribute))
    return;  // No change
  LayoutObject* layout_object = element_->GetLayoutObject();
  if (!layout_object)
    return;
  layout_object->SetNeedsPaintPropertyUpdate();
  MarkFilterDataDirty();
  LayoutSVGResourceContainer::InvalidateDependentElements(*layout_object,
                                                          false);
  LayoutSVGResourceContainer::InvalidateAncestorChainResources(*layout_object,
                                                               false);
}

SVGElementResourceClient::FilterData*
SVGElementResourceClient::CreateFilterDataWithNodeMap(
    FilterEffectBuilder& builder,
    const ReferenceFilterOperation& reference_filter) {
  auto* node_map = MakeGarbageCollected<SVGFilterGraphNodeMap>();
  Filter* filter =
      builder.BuildReferenceFilter(reference_filter, nullptr, node_map);
  if (!filter)
    return nullptr;
  paint_filter_builder::PopulateSourceGraphicImageFilters(
      filter->GetSourceGraphic(), kInterpolationSpaceSRGB);
  return MakeGarbageCollected<FilterData>(filter->LastEffect(), node_map);
}

void SVGElementResourceClient::UpdateFilterData(
    CompositorFilterOperations& operations) {
  DCHECK(element_->GetLayoutObject());
  const LayoutObject& object = *element_->GetLayoutObject();
  gfx::RectF reference_box = SVGResources::ReferenceBoxForEffects(object);
  if (!operations.IsEmpty() && !filter_data_dirty_ &&
      reference_box == operations.ReferenceBox())
    return;
  const ComputedStyle& style = object.StyleRef();
  FilterEffectBuilder builder(
      reference_box, std::nullopt, 1,
      style.VisitedDependentColor(GetCSSPropertyColor()),
      style.UsedColorScheme());
  builder.SetShorthandScale(1 / style.EffectiveZoom());
  const FilterOperations& filter = style.Filter();
  // If the filter is a single 'url(...)' reference we can optimize some
  // mutations to the referenced filter chain by tracking the filter
  // dependencies and only perform partial invalidations of the filter chain.
  const bool is_single_reference_filter =
      filter.size() == 1 && IsA<ReferenceFilterOperation>(*filter.at(0));
  if (is_single_reference_filter) {
    if (!filter_data_) {
      filter_data_ = CreateFilterDataWithNodeMap(
          builder, To<ReferenceFilterOperation>(*filter.at(0)));
    }
    operations.Clear();
    if (filter_data_) {
      // If the referenced filter exists but does not contain any primitives,
      // then the rendering of the element should be disabled.
      if (filter_data_->HasEffects()) {
        // BuildPaintFilter() can return null which means pass-through.
        operations.AppendReferenceFilter(filter_data_->BuildPaintFilter());
      } else {
        // Create a filter chain that yields transparent black.
        operations.AppendOpacityFilter(0);
      }
    }
  } else {
    // Drop any existing filter data since the filter is no longer
    // cacheable.
    if (FilterData* filter_data = filter_data_.Release())
      filter_data->Dispose();

    operations = builder.BuildFilterOperations(filter);
  }
  operations.SetReferenceBox(reference_box);
  filter_data_dirty_ = false;
}

void SVGElementResourceClient::InvalidateFilterData() {
  // If we performed an "optimized" invalidation via FilterPrimitiveChanged(),
  // we could have set |filter_data_dirty_| but not cleared |filter_data_|.
  if (filter_data_dirty_ && !filter_data_)
    return;
  if (FilterData* filter_data = filter_data_.Release())
    filter_data->Dispose();
  if (LayoutObject* layout_object = element_->GetLayoutObject()) {
    layout_object->SetNeedsPaintPropertyUpdate();
    MarkFilterDataDirty();
  }
}

void SVGElementResourceClient::MarkFilterDataDirty() {
  DCHECK(element_->GetLayoutObject());
  DCHECK(element_->GetLayoutObject()->NeedsPaintPropertyUpdate());
  filter_data_dirty_ = true;
}

void SVGElementResourceClient::Trace(Visitor* visitor) const {
  visitor->Trace(element_);
  visitor->Trace(filter_data_);
  SVGResourceClient::Trace(visitor);
}

SVGResourceInvalidator::SVGResourceInvalidator(LayoutObject& object)
    : object_(object) {}

void SVGResourceInvalidator::InvalidateEffects() {
  const ComputedStyle& style = object_.StyleRef();
  if (style.HasFilter()) {
    if (SVGElementResourceClient* client = SVGResources::GetClient(object_))
      client->InvalidateFilterData();
  }
  if (style.HasClipPath() || style.HasMask()) {
    object_.SetShouldDoFullPaintInvalidation();
    object_.SetNeedsPaintPropertyUpdate();
  }
}

void SVGResourceInvalidator::InvalidatePaints() {
  SVGElementResourceClient* client = SVGResources::GetClient(object_);
  if (!client)
    return;
  bool needs_invalidation = false;
  const ComputedStyle& style = object_.StyleRef();
  if (auto* fill = GetSVGResourceAsType<LayoutSVGResourcePaintServer>(
          *client, style.FillPaint().Resource())) {
    fill->RemoveClientFromCache(*client);
    needs_invalidation = true;
  }
  if (auto* stroke = GetSVGResourceAsType<LayoutSVGResourcePaintServer>(
          *client, style.StrokePaint().Resource())) {
    stroke->RemoveClientFromCache(*client);
    needs_invalidation = true;
  }
  if (!needs_invalidation)
    return;
  object_.SetSubtreeShouldDoFullPaintInvalidation(
      PaintInvalidationReason::kSVGResource);
}

}  // namespace blink
```