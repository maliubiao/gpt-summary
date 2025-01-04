Response:
Let's break down the thought process for analyzing this C++ code and generating the explanation.

1. **Understand the Core Objective:** The fundamental goal is to explain the functionality of the `LayoutSVGResourceContainer.cc` file within the Chromium Blink rendering engine. This involves identifying its purpose, its interactions with other parts of the system (especially JavaScript, HTML, and CSS), and potential issues or common errors.

2. **Initial Code Scan - Identify Key Components:**  Read through the code, looking for important classes, methods, and data structures. Keywords like `LayoutSVGResourceContainer`, `SVGResource`, `Invalidate`, `ResolveRectangle`, `FindCycle`, and mentions of `HTML`, `CSS`, and `JavaScript` (though not explicitly present in this file) are crucial. Note the included header files – they give hints about dependencies and related concepts.

3. **Focus on the Class Definition:** The `LayoutSVGResourceContainer` class itself is the primary subject. Understand its inheritance (`LayoutSVGHiddenContainer`) and member variables (`completed_invalidations_mask_`, `is_invalidating_`). This provides context about its role in the layout process and its state.

4. **Analyze Key Methods:**  Go through each public method and understand its purpose:
    * **Constructor/Destructor:**  Basic lifecycle management.
    * **`UpdateSVGLayout`:**  Part of the layout process, specifically for clearing invalidation flags.
    * **`ResolveRectangle` (various overloads):**  Crucial for understanding how SVG coordinates and dimensions are calculated, considering different units (`objectBoundingBox`, `userSpaceOnUse`). This is a significant area for interaction with HTML/CSS.
    * **`InvalidateClientsIfActiveResource`:**  Important for understanding how changes to resources propagate.
    * **`WillBeDestroyed`:**  Cleanup actions when the object is being destroyed.
    * **`StyleDidChange`:**  Handles updates when the style associated with the element changes.
    * **`FindCycle` (and related methods):**  Addresses the critical issue of circular dependencies in SVG resources.
    * **`MarkAllClientsForInvalidation`:**  Another mechanism for triggering updates when a resource changes.
    * **`InvalidateCache`:**  Manages caching related to the resource.
    * **`InvalidateDependentElements`, `InvalidateAncestorChainResources`, `MarkForLayoutAndParentResourceInvalidation`:**  Methods for propagating invalidations through the DOM tree.
    * **`StyleChanged`:**  Handles style changes specific to objects within a resource container.

5. **Identify Relationships with HTML, CSS, and JavaScript:**
    * **HTML:** The `SVGElement* node` in the constructor clearly links this to the HTML DOM. The concept of resource IDs (using `GetIdAttribute()`) connects to how SVG elements are referenced in HTML.
    * **CSS:**  The `ComputedStyle` is heavily used in methods like `ResolveRectangle` and `FindCycleInResources`. CSS properties like `clip-path`, `filter`, `marker`, `fill`, and `stroke` are directly mentioned, showing how CSS influences SVG rendering.
    * **JavaScript:** While this specific file doesn't directly interact with JavaScript code, it's part of the rendering pipeline that *responds* to changes caused by JavaScript. For instance, JavaScript manipulating the `id` of an SVG element or changing CSS properties that affect SVG resources would trigger the mechanisms handled by this file.

6. **Infer Logic and Provide Examples:** For methods like `ResolveRectangle`, think about the different input scenarios (e.g., using percentages with `objectBoundingBox` vs. `userSpaceOnUse`) and how the code handles them. Construct hypothetical examples to illustrate the input and output.

7. **Consider User/Programming Errors:** Think about common mistakes developers might make when working with SVG resources. Circular dependencies are a classic issue, and this code has logic to detect them. Incorrectly specifying units in SVG attributes is another potential problem that the coordinate resolution functions might encounter.

8. **Structure the Explanation:** Organize the information logically. Start with a high-level summary of the file's purpose. Then, detail the key functionalities, providing examples and explaining relationships to HTML, CSS, and JavaScript. Finally, address potential errors.

9. **Refine and Clarify:** Review the explanation for clarity and accuracy. Use precise language and avoid jargon where possible. Ensure the examples are easy to understand and directly illustrate the concepts being explained. For instance, explicitly stating the formulas for percentage calculations in different unit types makes the `ResolveRectangle` function's purpose clearer.

10. **Self-Correction/Refinement during the process:**
    * Initially, I might have focused too much on the internal implementation details. It's important to shift the focus to the *functionality* and its impact on the overall rendering process.
    *  Realizing that JavaScript interaction is implicit rather than explicit in this file is crucial. Focus on how the code *responds* to JavaScript-initiated changes.
    *  Making sure the examples are concrete and easy to grasp is an iterative process. I might start with a more abstract example and then refine it to be more specific and illustrative.
    * Double-checking the meaning of specific terms like "invalidation" and "resource" within the context of the Blink rendering engine is essential for accuracy.

By following this structured approach, combining code analysis with a understanding of web technologies (HTML, CSS, JavaScript) and potential developer pitfalls, one can generate a comprehensive and informative explanation of the given source code file.
这个文件 `blink/renderer/core/layout/svg/layout_svg_resource_container.cc` 的主要功能是 **管理和处理 SVG 资源的布局和生命周期**。它定义了 `LayoutSVGResourceContainer` 类，这个类专门用于布局那些作为 SVG 资源的元素，例如 `<filter>`, `<clipPath>`, `<marker>`, `<linearGradient>`, `<radialGradient>`, `<pattern>`, `<mask>` 等。

以下是它的具体功能分解：

**1. 作为 SVG 资源的布局容器:**

*   `LayoutSVGResourceContainer` 继承自 `LayoutSVGHiddenContainer`，这意味着它在布局树中通常是隐藏的，不会直接渲染到屏幕上。它的主要作用是作为其他 SVG 元素使用的资源的容器。
*   它持有对关联的 `SVGElement` 的引用，这个 `SVGElement` 就是定义的 SVG 资源本身。

**2. 管理资源失效和更新:**

*   **资源失效通知:** 当资源的内容发生变化（例如，其内部元素或属性被修改）时，`LayoutSVGResourceContainer` 负责通知所有使用了该资源的客户端（例如，应用了该滤镜或遮罩的元素）进行更新。
*   **`InvalidateClientsIfActiveResource()`:**  这个方法检查当前资源是否是拥有特定 ID 的第一个元素（"active" 资源）。如果是，它会通知文档调度资源失效，从而触发依赖该资源的元素的重新渲染或重新布局。
*   **`MarkAllClientsForInvalidation()`:**  这个方法用于标记所有使用该资源的客户端进行失效，可以指定不同的失效模式。
*   **`StyleDidChange()`:**  当资源元素的样式发生变化时被调用。如果资源刚刚被添加到 DOM 树中，它会调用 `InvalidateClientsIfActiveResource()` 来通知客户端。

**3. 处理 SVG 长度和坐标的解析:**

*   **`ResolveRectangle()` (多个重载):**  这个关键方法负责将 SVG 中定义的长度值（例如，`<rect>` 的 `x`, `y`, `width`, `height` 属性）解析为具体的像素值。它需要考虑不同的单位类型 (`userSpaceOnUse`, `objectBoundingBox`) 和上下文信息（例如，引用的元素、视口大小）。
    *   **`objectBoundingBox` 单位:**  如果指定了 `objectBoundingBox`，长度值会相对于应用该资源的元素的边界框进行解析。
    *   **`userSpaceOnUse` 单位:** 如果指定了 `userSpaceOnUse`，长度值会相对于当前用户坐标系统进行解析。
*   这个方法与 CSS 的单位解析机制有相似之处，但专门处理 SVG 的长度单位和坐标系统。

**4. 检测循环依赖:**

*   **`FindCycle()` 和相关方法 (`FindCycleFromSelf()`, `FindCycleInResources()`, `FindCycleInDescendants()`, `FindCycleInSubtree()`):**  SVG 资源可以相互引用，例如，一个滤镜可以引用另一个滤镜。如果形成循环引用（A 引用 B，B 又引用 A），会导致无限循环。这些方法用于检测这种循环依赖，防止渲染引擎崩溃或进入无限循环。

**5. 缓存管理:**

*   **`InvalidateCache()`:** 清除与该资源相关的缓存，强制客户端重新评估资源的内容。
*   **`RemoveAllClientsFromCache()`:**  从缓存中移除所有客户端。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

*   **HTML:**
    *   `LayoutSVGResourceContainer` 对应于 HTML 中的 SVG 元素，这些元素定义了可重用的资源。例如：
        ```html
        <svg>
          <filter id="myBlur">
            <feGaussianBlur in="SourceGraphic" stdDeviation="5" />
          </filter>
          <rect x="10" y="10" width="100" height="100" style="filter: url(#myBlur);" />
        </svg>
        ```
        这里的 `<filter id="myBlur">` 对应的布局对象就是一个 `LayoutSVGResourceContainer`。
    *   当 HTML 中 SVG 资源的定义发生变化（例如，修改了 `<feGaussianBlur>` 的 `stdDeviation`），`LayoutSVGResourceContainer` 会触发更新。

*   **CSS:**
    *   CSS 属性可以引用 SVG 资源，例如 `filter: url(#myBlur);`, `clip-path: url(#myClip);`, `mask: url(#myMask);` 等。
    *   当应用了引用 SVG 资源的 CSS 规则的元素需要布局或绘制时，会涉及到 `LayoutSVGResourceContainer` 来解析资源的内容和尺寸。
    *   **举例:**  如果 CSS 样式改变，导致一个元素开始或停止使用某个 SVG 滤镜，`LayoutSVGResourceContainer` 的 `StyleDidChange()` 方法会被调用。

*   **JavaScript:**
    *   JavaScript 可以动态地修改 SVG 元素的属性，从而改变 SVG 资源的内容。
    *   **举例:**  如果 JavaScript 使用 DOM API 修改了上面 `myBlur` 滤镜的 `stdDeviation` 值：
        ```javascript
        document.getElementById('myBlur').querySelector('feGaussianBlur').setAttribute('stdDeviation', '10');
        ```
        这将导致与 `myBlur` 关联的 `LayoutSVGResourceContainer` 标记使用该滤镜的元素需要重新渲染。
    *   JavaScript 还可以创建或删除 SVG 资源元素，这会影响 `LayoutSVGResourceContainer` 的创建和销毁。

**逻辑推理的假设输入与输出:**

假设有一个 `<rect>` 元素应用了一个裁剪路径 `<clipPath>`：

**假设输入:**

1. **HTML:**
    ```html
    <svg>
      <clipPath id="myClip">
        <circle cx="50" cy="50" r="40" />
      </clipPath>
      <rect x="0" y="0" width="100" height="100" style="clip-path: url(#myClip);" />
    </svg>
    ```
2. **布局过程:**  当布局引擎处理 `<rect>` 元素时，它会遇到 `clip-path: url(#myClip);`。

**逻辑推理过程:**

1. 引擎会查找 ID 为 `myClip` 的 SVG 资源，并找到对应的 `LayoutSVGResourceContainer`。
2. `LayoutSVGResourceContainer` 中的 `ResolveRectangle()` (或其他相关的解析方法) 会被调用，用于确定裁剪路径的形状和大小。这可能涉及到解析 `<circle>` 元素的 `cx`, `cy`, `r` 属性。
3. `ResolveRectangle()` 需要考虑 `clipPath` 元素的单位类型（默认为 `userSpaceOnUse`）。
4. 最终，`ResolveRectangle()` 会输出裁剪路径的几何信息，供 `<rect>` 元素进行裁剪。

**输出:**

*   `<rect>` 元素会被圆形裁剪路径裁剪，只有位于圆形内部的部分会显示出来。

**用户或编程常见的使用错误举例:**

1. **循环引用导致渲染问题:**
    ```html
    <svg>
      <filter id="filterA" filterUnits="objectBoundingBox">
        <feGaussianBlur in="SourceGraphic" stdDeviation="0.05" result="blur"/>
        <feColorMatrix in="blur" type="matrix" values="..."/>
        <feBlend in="SourceGraphic" in2="filterB"/> </filter> <filter id="filterB" filterUnits="objectBoundingBox"> <feOffset dx="0.01" dy="0.01" in="SourceGraphic" result="offset"/> <feBlend in="SourceGraphic" in2="filterA"/> </filter> <rect x="10" y="10" width="100" height="100" style="filter: url(#filterA);" />
    </svg>
    ```
    在这个例子中，`filterA` 引用了 `filterB`，而 `filterB` 又引用了 `filterA`，形成循环依赖。现代浏览器通常能检测到这种循环，但可能会导致性能问题或渲染错误。`LayoutSVGResourceContainer` 的 `FindCycle()` 方法就是为了防止这种情况。

2. **错误的单位类型导致意想不到的布局:**
    ```html
    <svg viewBox="0 0 100 100">
      <clipPath id="myClip" clipPathUnits="objectBoundingBox">
        <rect x="0.1" y="0.1" width="0.8" height="0.8" />
      </clipPath>
      <rect x="0" y="0" width="200" height="200" style="clip-path: url(#myClip);" />
    </svg>
    ```
    这里的 `<clipPath>` 使用了 `objectBoundingBox` 单位，这意味着 `<rect>` 的裁剪路径是其自身边界框的 10% 到 90%。 如果开发者期望裁剪路径相对于 SVG 视口 (`viewBox`)，则会得到意外的结果。理解 `userSpaceOnUse` 和 `objectBoundingBox` 的区别对于正确使用 SVG 资源至关重要。`LayoutSVGResourceContainer` 的 `ResolveRectangle()` 方法需要正确处理这些不同的单位。

总而言之，`blink/renderer/core/layout/svg/layout_svg_resource_container.cc` 文件是 Blink 引擎中处理 SVG 资源布局和生命周期的核心组件，它负责资源的创建、更新、失效通知、坐标解析以及循环依赖检测，与 HTML、CSS 和 JavaScript 都有着密切的联系。

Prompt: 
```
这是目录为blink/renderer/core/layout/svg/layout_svg_resource_container.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
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

#include "third_party/blink/renderer/core/layout/svg/layout_svg_resource_container.h"

#include "third_party/blink/renderer/core/layout/svg/svg_layout_info.h"
#include "third_party/blink/renderer/core/layout/svg/svg_resources.h"
#include "third_party/blink/renderer/core/style/reference_clip_path_operation.h"
#include "third_party/blink/renderer/core/style/style_mask_source_image.h"
#include "third_party/blink/renderer/core/svg/svg_element.h"
#include "third_party/blink/renderer/core/svg/svg_length.h"
#include "third_party/blink/renderer/core/svg/svg_length_context.h"
#include "third_party/blink/renderer/core/svg/svg_resource.h"
#include "third_party/blink/renderer/core/svg/svg_tree_scope_resources.h"
#include "third_party/blink/renderer/platform/geometry/length_functions.h"

namespace blink {

namespace {

LocalSVGResource* ResourceForContainer(
    const LayoutSVGResourceContainer& resource_container) {
  const SVGElement& element = *resource_container.GetElement();
  return element.GetTreeScope()
      .EnsureSVGTreeScopedResources()
      .ExistingResourceForId(element.GetIdAttribute());
}

float ObjectBoundingBoxUnitToUserUnits(const Length& length,
                                       float ref_dimension) {
  // For "plain" percentages we resolve against the real reference dimension
  // and scale with the unit dimension to avoid losing precision for common
  // cases. In essence because of the difference between:
  //
  //   v * percentage / 100
  //
  // and:
  //
  //   v * (percentage / 100)
  //
  // for certain, common, values of v and percentage.
  float unit_dimension = 1;
  if (length.IsPercent()) {
    std::swap(unit_dimension, ref_dimension);
  }
  return FloatValueForLength(length, unit_dimension) * ref_dimension;
}

}  // namespace

LayoutSVGResourceContainer::LayoutSVGResourceContainer(SVGElement* node)
    : LayoutSVGHiddenContainer(node),
      completed_invalidations_mask_(0),
      is_invalidating_(false) {}

LayoutSVGResourceContainer::~LayoutSVGResourceContainer() = default;

SVGLayoutResult LayoutSVGResourceContainer::UpdateSVGLayout(
    const SVGLayoutInfo& layout_info) {
  NOT_DESTROYED();
  // TODO(fs): This is only here to clear the invalidation mask, without that
  // we wouldn't need to override LayoutSVGHiddenContainer::UpdateSVGLayout().
  DCHECK(NeedsLayout());
  ClearInvalidationMask();
  return LayoutSVGHiddenContainer::UpdateSVGLayout(layout_info);
}

gfx::RectF LayoutSVGResourceContainer::ResolveRectangle(
    const SVGViewportResolver& viewport_resolver,
    const SVGLengthConversionData& conversion_data,
    SVGUnitTypes::SVGUnitType type,
    const gfx::RectF& reference_box,
    const SVGLength& x,
    const SVGLength& y,
    const SVGLength& width,
    const SVGLength& height,
    const std::optional<gfx::SizeF>& override_viewport) {
  // Convert SVGLengths to Lengths (preserves percentages).
  const LengthPoint point(x.ConvertToLength(conversion_data),
                          y.ConvertToLength(conversion_data));
  const LengthSize size(width.ConvertToLength(conversion_data),
                        height.ConvertToLength(conversion_data));
  gfx::RectF resolved_rect;
  // If the requested unit is 'objectBoundingBox' then the resolved user units
  // are actually normalized (in bounding box units), so transform them to the
  // actual user space.
  if (type == SVGUnitTypes::kSvgUnitTypeObjectboundingbox) {
    // Resolve the Lengths to user units.
    resolved_rect = gfx::RectF(
        ObjectBoundingBoxUnitToUserUnits(point.X(), reference_box.width()),
        ObjectBoundingBoxUnitToUserUnits(point.Y(), reference_box.height()),
        ObjectBoundingBoxUnitToUserUnits(size.Width(), reference_box.width()),
        ObjectBoundingBoxUnitToUserUnits(size.Height(),
                                         reference_box.height()));
    resolved_rect += reference_box.OffsetFromOrigin();
  } else {
    DCHECK_EQ(type, SVGUnitTypes::kSvgUnitTypeUserspaceonuse);
    // Determine the viewport to use for resolving the Lengths to user units.
    gfx::SizeF viewport_size_for_resolve;
    if (size.Width().MayHavePercentDependence() ||
        size.Height().MayHavePercentDependence() || point.X().HasPercent() ||
        point.Y().HasPercent()) {
      viewport_size_for_resolve =
          override_viewport.value_or(viewport_resolver.ResolveViewport());
    }
    // Resolve the Lengths to user units.
    resolved_rect =
        gfx::RectF(PointForLengthPoint(point, viewport_size_for_resolve),
                   SizeForLengthSize(size, viewport_size_for_resolve));
  }
  return resolved_rect;
}

gfx::RectF LayoutSVGResourceContainer::ResolveRectangle(
    const SVGElement& context_element,
    SVGUnitTypes::SVGUnitType type,
    const gfx::RectF& reference_box,
    const SVGLength& x,
    const SVGLength& y,
    const SVGLength& width,
    const SVGLength& height,
    const std::optional<gfx::SizeF>& override_viewport) {
  const ComputedStyle* style =
      SVGLengthContext::ComputedStyleForLengthResolving(context_element);
  if (!style) {
    return gfx::RectF(0, 0, 0, 0);
  }
  const SVGViewportResolver viewport_resolver(context_element);
  const SVGLengthConversionData conversion_data(context_element, *style);
  return ResolveRectangle(viewport_resolver, conversion_data, type,
                          reference_box, x, y, width, height,
                          override_viewport);
}

gfx::RectF LayoutSVGResourceContainer::ResolveRectangle(
    SVGUnitTypes::SVGUnitType type,
    const gfx::RectF& reference_box,
    const SVGLength& x,
    const SVGLength& y,
    const SVGLength& width,
    const SVGLength& height) const {
  const SVGViewportResolver viewport_resolver(*this);
  const SVGLengthConversionData conversion_data(*this);
  return ResolveRectangle(viewport_resolver, conversion_data, type,
                          reference_box, x, y, width, height);
}

void LayoutSVGResourceContainer::InvalidateClientsIfActiveResource() {
  NOT_DESTROYED();
  // Avoid doing unnecessary work if the document is being torn down.
  if (DocumentBeingDestroyed())
    return;
  // If this is the 'active' resource (the first element with the specified 'id'
  // in tree order), notify any clients that they need to reevaluate the
  // resource's contents.
  LocalSVGResource* resource = ResourceForContainer(*this);
  if (!resource || resource->Target() != GetElement())
    return;
  GetDocument().ScheduleSVGResourceInvalidation(*resource);
}

void LayoutSVGResourceContainer::WillBeDestroyed() {
  NOT_DESTROYED();
  // The resource is being torn down.
  InvalidateClientsIfActiveResource();
  LayoutSVGHiddenContainer::WillBeDestroyed();
}

void LayoutSVGResourceContainer::StyleDidChange(
    StyleDifference diff,
    const ComputedStyle* old_style) {
  NOT_DESTROYED();
  LayoutSVGHiddenContainer::StyleDidChange(diff, old_style);
  if (old_style)
    return;
  // The resource has been attached.
  InvalidateClientsIfActiveResource();
}

bool LayoutSVGResourceContainer::FindCycle() const {
  NOT_DESTROYED();
  return FindCycleFromSelf();
}

static HeapVector<Member<SVGResource>> CollectResources(
    const LayoutObject& layout_object) {
  const ComputedStyle& style = layout_object.StyleRef();
  HeapVector<Member<SVGResource>> resources;
  if (auto* reference_clip =
          DynamicTo<ReferenceClipPathOperation>(style.ClipPath())) {
    resources.push_back(reference_clip->Resource());
  }
  for (const auto& operation : style.Filter().Operations()) {
    if (auto* reference_operation =
            DynamicTo<ReferenceFilterOperation>(*operation))
      resources.push_back(reference_operation->Resource());
  }
  if (auto* marker = style.MarkerStartResource())
    resources.push_back(marker->Resource());
  if (auto* marker = style.MarkerMidResource())
    resources.push_back(marker->Resource());
  if (auto* marker = style.MarkerEndResource())
    resources.push_back(marker->Resource());
  if (auto* paint_resource = style.FillPaint().Resource())
    resources.push_back(paint_resource->Resource());
  if (auto* paint_resource = style.StrokePaint().Resource())
    resources.push_back(paint_resource->Resource());
  return resources;
}

bool LayoutSVGResourceContainer::FindCycleInResources(
    const LayoutObject& layout_object) {
  if (!layout_object.IsSVG() || layout_object.IsText())
    return false;
  // Without an associated client, we will not reference any resources.
  if (SVGResourceClient* client = SVGResources::GetClient(layout_object)) {
    // Fetch all the referenced resources.
    HeapVector<Member<SVGResource>> resources = CollectResources(layout_object);
    // This performs a depth-first search for a back-edge in all the
    // (potentially disjoint) graphs formed by the referenced resources.
    for (const auto& local_resource : resources) {
      // The resource can be null if the reference is external but external
      // references are not allowed.
      if (local_resource && local_resource->FindCycle(*client)) {
        return true;
      }
    }
  }
  for (const FillLayer* layer = &layout_object.StyleRef().MaskLayers(); layer;
       layer = layer->Next()) {
    const auto* mask_source =
        DynamicTo<StyleMaskSourceImage>(layer->GetImage());
    if (!mask_source) {
      continue;
    }
    const SVGResource* svg_resource = mask_source->GetSVGResource();
    SVGResourceClient* client =
        mask_source->GetSVGResourceClient(layout_object);
    if (svg_resource && svg_resource->FindCycle(*client)) {
      return true;
    }
  }
  return false;
}

bool LayoutSVGResourceContainer::FindCycleFromSelf() const {
  NOT_DESTROYED();
  // Resources don't generally apply to other resources, so require
  // the specific cases that do (like <clipPath>) to implement an
  // override.
  return FindCycleInDescendants(*this);
}

bool LayoutSVGResourceContainer::FindCycleInDescendants(
    const LayoutObject& root) {
  LayoutObject* node = root.SlowFirstChild();
  while (node) {
    // Skip subtrees which are themselves resources. (They will be
    // processed - if needed - when they are actually referenced.)
    if (node->IsSVGResourceContainer()) {
      node = node->NextInPreOrderAfterChildren(&root);
      continue;
    }
    if (FindCycleInResources(*node))
      return true;
    node = node->NextInPreOrder(&root);
  }
  return false;
}

bool LayoutSVGResourceContainer::FindCycleInSubtree(
    const LayoutObject& root) {
  if (FindCycleInResources(root))
    return true;
  return FindCycleInDescendants(root);
}

void LayoutSVGResourceContainer::MarkAllClientsForInvalidation(
    InvalidationModeMask invalidation_mask) {
  NOT_DESTROYED();
  if (is_invalidating_)
    return;
  LocalSVGResource* resource = ResourceForContainer(*this);
  if (!resource || resource->Target() != GetElement())
    return;
  // Remove modes for which invalidations have already been
  // performed. If no modes remain we are done.
  invalidation_mask &= ~completed_invalidations_mask_;
  if (invalidation_mask == 0)
    return;
  completed_invalidations_mask_ |= invalidation_mask;

  auto& document = GetDocument();
  if (document.InStyleRecalc() ||
      document.GetStyleEngine().InDetachLayoutTree()) {
    document.ScheduleSVGResourceInvalidation(*resource);
  } else {
    is_invalidating_ = true;

    // Invalidate clients registered via an SVGResource.
    resource->NotifyContentChanged();

    is_invalidating_ = false;
  }
}

void LayoutSVGResourceContainer::InvalidateCache() {
  NOT_DESTROYED();
  if (EverHadLayout()) {
    RemoveAllClientsFromCache();
  }
}

static inline void RemoveFromCacheAndInvalidateDependencies(
    LayoutObject& object,
    bool needs_layout) {
  if (!RuntimeEnabledFeatures::SvgTransformOptimizationEnabled()) {
    if (object.IsSVG()) {
      SVGResourceInvalidator(object).InvalidateEffects();
    }
  }

  LayoutSVGResourceContainer::InvalidateDependentElements(object, needs_layout);
}

void LayoutSVGResourceContainer::InvalidateDependentElements(
    LayoutObject& object,
    bool needs_layout) {
  auto* element = DynamicTo<SVGElement>(object.GetNode());
  if (!element)
    return;
  element->NotifyIncomingReferences([needs_layout](SVGElement& element) {
    DCHECK(element.GetLayoutObject());
    LayoutSVGResourceContainer::MarkForLayoutAndParentResourceInvalidation(
        *element.GetLayoutObject(), needs_layout);
  });
}

void LayoutSVGResourceContainer::InvalidateAncestorChainResources(
    LayoutObject& object,
    bool needs_layout) {
  LayoutObject* current = object.Parent();
  while (current) {
    RemoveFromCacheAndInvalidateDependencies(*current, needs_layout);

    if (current->IsSVGResourceContainer()) {
      // This will process the rest of the ancestors.
      To<LayoutSVGResourceContainer>(current)->RemoveAllClientsFromCache();
      break;
    }

    current = current->Parent();
  }
}

void LayoutSVGResourceContainer::MarkForLayoutAndParentResourceInvalidation(
    LayoutObject& object,
    bool needs_layout) {
  DCHECK(object.GetNode());

  if (needs_layout && !object.DocumentBeingDestroyed()) {
    object.SetNeedsLayoutAndFullPaintInvalidation(
        layout_invalidation_reason::kSvgResourceInvalidated);
  }

  RemoveFromCacheAndInvalidateDependencies(object, needs_layout);
  InvalidateAncestorChainResources(object, needs_layout);
}

static inline bool IsLayoutObjectOfResourceContainer(
    const LayoutObject& layout_object) {
  const LayoutObject* current = &layout_object;
  while (current) {
    if (current->IsSVGResourceContainer())
      return true;
    current = current->Parent();
  }
  return false;
}

void LayoutSVGResourceContainer::StyleChanged(LayoutObject& object,
                                              StyleDifference diff) {
  // If this LayoutObject is the child of a resource container and
  // it requires repainting because of changes to CSS properties
  // such as 'visibility', upgrade to invalidate layout.
  bool needs_layout = diff.NeedsNormalPaintInvalidation() &&
                      IsLayoutObjectOfResourceContainer(object);
  MarkForLayoutAndParentResourceInvalidation(object, needs_layout);
}

}  // namespace blink

"""

```