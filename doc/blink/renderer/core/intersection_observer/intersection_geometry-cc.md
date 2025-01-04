Response:
The user wants to understand the functionality of the `intersection_geometry.cc` file in the Chromium Blink rendering engine. They are interested in its relation to web technologies (JavaScript, HTML, CSS), logical reasoning with examples, common user/programming errors, and a summary of its functions based on the provided code snippet.

**Plan:**

1. **Analyze the code:**  Identify the key classes, functions, and data structures used in the provided snippet.
2. **Determine the file's purpose:** Based on the code and its location, figure out the primary role of `intersection_geometry.cc`.
3. **Explain functionalities:** Break down the main tasks performed by the code, such as calculating intersections, handling margins, and dealing with coordinate transformations.
4. **Relate to web technologies:**  Connect the code's functionalities to how they manifest in JavaScript's `IntersectionObserver` API, and how HTML and CSS properties influence these calculations.
5. **Provide logical reasoning examples:**  Create scenarios with input (e.g., element positions, root boundaries) and explain how the code would calculate the intersection.
6. **Identify common errors:**  Point out potential mistakes developers or the browser might make that could lead to incorrect intersection calculations.
7. **Summarize the functionality:**  Concisely describe the core responsibilities of the `intersection_geometry.cc` file based on the analysis.
```
功能：
这个文件 `intersection_geometry.cc` 实现了 Chromium Blink 渲染引擎中 Intersection Observer API 的核心几何计算逻辑。它的主要功能是确定一个目标元素与一个根元素（可以是视口或另一个元素）的交叉情况，包括交叉的矩形区域和交叉比例。

具体来说，它负责：

1. **初始化根元素和目标元素的几何信息:**
   - 获取根元素和目标元素的布局信息（LayoutObject）。
   - 计算根元素的初始交叉矩形（InitializeRootRect），考虑到主框架的特殊情况。
   - 计算目标元素的初始矩形（InitializeTargetRect），根据元素类型（Box, Inline, Text, SVG）选择合适的边界。

2. **处理边距 (Margins):**
   - 解析根元素和目标元素上设置的边距（`rootMargin`, `targetMargin`, `scrollMargin`）。
   - 将边距值（可以是像素或百分比）转换为物理像素。
   - 将边距应用于根元素和目标元素的矩形。

3. **计算交叉矩形 (Intersection Rect):**
   - 将目标元素的矩形映射到根元素的坐标系中。
   - 根据根元素的边界（包括可能的滚动和裁剪）裁剪目标元素的矩形，得到交叉矩形。
   - 处理嵌套的滚动容器，将裁剪和边距应用于每个中间滚动容器。

4. **计算交叉比例 (Intersection Ratio):**
   - 根据交叉矩形和用于比较的矩形（可以是根元素的矩形或目标元素的矩形）计算交叉比例。
   - 考虑到目标元素可能面积为零的情况。

5. **计算可见性 (Visibility):**
   - 判断目标元素是否被其他绘制在它之上的内容遮挡。
   - 使用 Hit Testing 来检测遮挡元素。
   - 如果启用了 `kShouldExposeOccluderNodeId` 标志，则记录遮挡元素的 DOM 节点 ID。

6. **坐标系转换:**
   - 在不同的坐标系之间转换矩形，例如从元素的局部坐标系到视口坐标系。
   - 处理 transform 属性的影响。

7. **性能优化:**
   - 尝试使用 `GeometryMapper` 来进行更快的坐标转换。
   - 实现缓存机制 (`CachedRects`)，在某些情况下可以避免重复计算。

8. **处理不同的根元素类型:**
   - 支持显式的根元素和隐式的根元素（视口）。
   - 针对 iframe 中的目标元素进行特殊处理。

9. **处理裁剪 (Clipping):**
   - 考虑元素的 `overflow`、`clip-path`、`mask` 等属性对交叉计算的影响。

与 javascript, html, css 的功能关系：

* **JavaScript:** 这个文件是 Intersection Observer API 在 Blink 渲染引擎中的底层实现，JavaScript 代码通过 `IntersectionObserver` 构造函数和回调函数来使用这些功能。例如，在 JavaScript 中设置 `rootMargin` 属性，最终会调用到这个文件中处理边距的逻辑。
  ```javascript
  const observer = new IntersectionObserver(entries => {
    entries.forEach(entry => {
      console.log(entry.intersectionRatio); // 这里的值由 intersection_geometry.cc 计算得出
      console.log(entry.intersectionRect); // 这里的值由 intersection_geometry.cc 计算得出
      console.log(entry.rootBounds);     // 如果设置了 kShouldReportRootBounds 标志
    });
  }, {
    rootMargin: '10px 20px 30px 40px', // 影响 ApplyMargin 函数
    threshold: 0.5                     // 影响 FirstThresholdGreaterThan 函数
  });
  ```

* **HTML:** HTML 结构定义了元素的层次关系和布局，这直接影响了交叉计算中坐标系的转换和裁剪的逻辑。例如，一个元素是否在滚动容器内，会影响 `ClipToRoot` 函数的处理。
  ```html
  <div style="overflow: auto; width: 200px; height: 100px;">
    <div id="target" style="width: 50px; height: 50px;"></div>
  </div>
  ```
  在这个例子中，`#target` 元素的交叉情况会受到外层 `div` 的滚动影响，`intersection_geometry.cc` 会处理这种关系。

* **CSS:** CSS 样式属性，如 `width`, `height`, `margin`, `padding`, `border`, `transform`, `overflow`, `clip-path`, `mask` 等，都会影响元素的几何信息和渲染结果，从而影响交叉计算。
  ```css
  #target {
    width: 100px;
    height: 100px;
    transform: translateX(50px); /* 影响 ObjectToViewTransform 函数 */
    clip-path: circle(50px at 50px 50px); /* 影响 ApplyClip 函数 */
  }
  ```
  CSS 的 `transform` 属性会导致元素的局部坐标系发生变化，`intersection_geometry.cc` 中的 `ObjectToViewTransform` 函数负责处理这些变换。 `clip-path` 会裁剪元素的可见区域，`ApplyClip` 函数会考虑这些裁剪。

逻辑推理的假设输入与输出：

**假设输入 1:**
- 根元素 (root): 视口 (隐式根)
- 目标元素 (target): 一个位于页面左上角的 50x50 像素的 `div` 元素。
- `thresholds`: `[0, 0.5, 1]`

**预期输出 1:**
- 初始状态，目标元素完全在视口内，`intersectionRatio` 为 1，`thresholdIndex` 为 2 (对应阈值 1)。
- 当用户向下滚动页面，目标元素一半移出视口时，`intersectionRatio` 接近 0.5， `thresholdIndex` 可能变为 1 (对应阈值 0.5)。
- 当目标元素完全移出视口时，`intersectionRatio` 为 0，`thresholdIndex` 为 0。

**假设输入 2:**
- 根元素 (root): 一个 200x100 像素的 `div` 元素，设置了 `overflow: auto`。
- 目标元素 (target): 一个位于根元素内的 50x50 像素的 `div` 元素。
- `rootMargin`: `'10px'` (所有方向)

**预期输出 2:**
- 根元素的有效交叉区域会因为 `rootMargin` 向内缩小 10 像素。
- 初始状态，如果目标元素在根元素的有效交叉区域内，`intersectionRatio` 大于 0。
- 当滚动根元素，目标元素移出根元素的有效交叉区域时，`intersectionRatio` 变为 0。

用户或编程常见的使用错误：

1. **错误的 `root` 选择:**  将不包含目标元素的元素设置为 `root`，会导致永远无法交叉。
   ```javascript
   const root = document.getElementById('some-other-element');
   const target = document.getElementById('target-element');
   const observer = new IntersectionObserver(..., { root: root });
   observer.observe(target); // 如果 target 不在 root 的子树中，将永远不会触发回调
   ```

2. **不理解 `rootMargin` 的作用范围:**  `rootMargin` 是应用于根元素的边界框的，用于扩展或缩小根元素的有效交叉区域，单位可以是像素或百分比。 误解其工作方式会导致预期的交叉时机不符。
   ```javascript
   const observer = new IntersectionObserver(entries => { ... }, { rootMargin: '-50px 0px 0px 0px' });
   // 这个 rootMargin 会将根元素的顶部边界向上移动 50px，提前触发交叉。
   ```

3. **混淆 `threshold` 的含义:** `threshold` 是一个介于 0 和 1 之间的数字或数组，表示目标元素与根元素交叉比例达到多少时触发回调。 误设 `threshold` 会导致回调触发不符合预期。
   ```javascript
   const observer = new IntersectionObserver(entries => { ... }, { threshold: [0.25, 0.5, 0.75] });
   // 回调会在目标元素交叉比例达到 25%, 50%, 75% 时分别触发。
   ```

4. **忘记调用 `observe()` 方法:** 创建 `IntersectionObserver` 对象后，必须调用其 `observe()` 方法来监听目标元素。
   ```javascript
   const observer = new IntersectionObserver(entries => { ... });
   const target = document.getElementById('target');
   // observer.observe(target); // 忘记调用，不会监听
   ```

5. **在复杂的布局中使用 Intersection Observer 而不理解其原理:**  在复杂的布局（例如包含 transform、嵌套滚动容器、clip-path 等）中，Intersection Observer 的行为可能不太直观。不理解其底层的几何计算原理会导致难以调试问题。

总结功能 (第 1 部分):

在提供的代码片段中，`intersection_geometry.cc` 的主要功能是**计算根元素和目标元素的基本几何信息，包括它们的初始矩形和边距处理。它还实现了 `RootGeometry` 类，用于存储和更新根元素的几何信息。**  这部分代码为后续的交叉计算和可见性判断奠定了基础。 特别是 `InitializeRootRect`, `InitializeTargetRect`, `ComputeMargin`, `ApplyMargin`, 以及 `IntersectionGeometry::RootGeometry` 类的相关方法是核心。
```
Prompt: 
```
这是目录为blink/renderer/core/intersection_observer/intersection_geometry.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/intersection_observer/intersection_geometry.h"

#include "base/numerics/safe_conversions.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_utilities.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/intersection_observer/intersection_observer_entry.h"
#include "third_party/blink/renderer/core/layout/adjust_for_absolute_zoom.h"
#include "third_party/blink/renderer/core/layout/hit_test_result.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/layout_embedded_content.h"
#include "third_party/blink/renderer/core/layout/layout_inline.h"
#include "third_party/blink/renderer/core/layout/layout_text.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/paint/clip_path_clipper.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/platform/graphics/paint/geometry_mapper.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"

namespace blink {

namespace {

// Convert a Length value to physical pixels.
LayoutUnit ComputeMargin(const Length& length,
                         float reference_length,
                         float zoom) {
  if (length.IsPercent()) {
    return LayoutUnit(
        static_cast<int>(reference_length * length.Percent() / 100.0));
  }
  DCHECK(length.IsFixed());
  return LayoutUnit(length.Value() * zoom);
}

PhysicalBoxStrut ResolveMargin(const Vector<Length>& margin,
                               const gfx::SizeF& reference_size,
                               float zoom) {
  DCHECK_EQ(margin.size(), 4u);

  return PhysicalBoxStrut(
      ComputeMargin(margin[0], reference_size.height(), zoom),
      ComputeMargin(margin[1], reference_size.width(), zoom),
      ComputeMargin(margin[2], reference_size.height(), zoom),
      ComputeMargin(margin[3], reference_size.width(), zoom));
}

// Expand rect by the given margin values.
void ApplyMargin(gfx::RectF& expand_rect,
                 const Vector<Length>& margin,
                 float zoom,
                 const gfx::SizeF& reference_size) {
  if (margin.empty()) {
    return;
  }
  expand_rect.Outset(
      gfx::OutsetsF(ResolveMargin(margin, reference_size, zoom)));
}

// Returns the root intersect rect for the given root object, before applying
// margins, in the coordinate system of the root object.
//
// https://w3c.github.io/IntersectionObserver/#intersectionobserver-root-intersection-rectangle
gfx::RectF InitializeRootRect(const LayoutObject* root) {
  PhysicalRect result;
  auto* layout_view = DynamicTo<LayoutView>(root);
  if (layout_view && root->GetDocument().GetFrame()->IsOutermostMainFrame()) {
    // The main frame is a bit special as the scrolling viewport can differ in
    // size from the LayoutView itself. There's two situations this occurs in:
    // 1) The ForceZeroLayoutHeight quirk setting is used in Android WebView for
    // compatibility and sets the initial-containing-block's (a.k.a.
    // LayoutView) height to 0. Thus, we can't use its size for intersection
    // testing. Use the FrameView geometry instead.
    // 2) An element wider than the ICB can cause us to resize the FrameView so
    // we can zoom out to fit the entire element width.
    result = layout_view->OverflowClipRect(PhysicalOffset());
  } else if (auto* layout_box = DynamicTo<LayoutBox>(root)) {
    if (layout_box->ShouldClipOverflowAlongBothAxis()) {
      // TODO(https://github.com/w3c/IntersectionObserver/issues/518):
      // This doesn't strictly conform to the current spec (which says we
      // should use the padding box rect) when there is overflow-clip-margin.
      // We should also consider overflow-clip along only one axis.
      result = layout_box->OverflowClipRect(PhysicalOffset());
    } else {
      result = layout_box->PhysicalBorderBoxRect();
    }
  } else {
    result = To<LayoutInline>(root)->PhysicalLinesBoundingBox();
  }
  return gfx::RectF(result);
}

gfx::RectF GetBoxBounds(const LayoutBox* box, bool use_overflow_clip_edge) {
  PhysicalRect bounds(box->PhysicalBorderBoxRect());
  // Only use overflow clip rect if we need to use overflow clip edge and
  // overflow clip margin may have an effect, meaning we clip to the overflow
  // clip edge and not something else.
  if (use_overflow_clip_edge && box->ShouldApplyOverflowClipMargin()) {
    // OverflowClipRect() may be larger than PhysicalBorderBoxRect().
    bounds.Unite(box->OverflowClipRect(PhysicalOffset()));
  }
  return gfx::RectF(bounds);
}

// Return the bounding box of target in target's own coordinate system.
gfx::RectF InitializeTargetRect(const LayoutObject* target, unsigned flags) {
  if (flags & IntersectionGeometry::kForFrameViewportIntersection) {
    return gfx::RectF(To<LayoutEmbeddedContent>(target)->ReplacedContentRect());
  }
  if (target->IsSVGChild()) {
    return target->DecoratedBoundingBox();
  }
  if (auto* layout_box = DynamicTo<LayoutBox>(target)) {
    return GetBoxBounds(layout_box,
                        flags & IntersectionGeometry::kUseOverflowClipEdge);
  }
  if (auto* layout_inline = DynamicTo<LayoutInline>(target)) {
    return layout_inline->LocalBoundingBoxRectF();
  }
  return gfx::RectF(To<LayoutText>(target)->PhysicalLinesBoundingBox());
}

struct VisibilityInfo {
  bool is_visible = false;
  DOMNodeId occluder_node_id = kInvalidDOMNodeId;
};

// When the return value has `is_visible` as true, it means target has visual
// effects applied, or if rect, given in absolute coordinates, is overlapped by
// any content painted after target
//
// The `occluder_node_id` holds the ID of the node that's overlapping the target
// (if there is one) as the result of hit testing.
// https://w3c.github.io/IntersectionObserver/v2/#calculate-visibility-algo
VisibilityInfo ComputeVisibilityInfo(const LayoutObject* target,
                                     const PhysicalRect& rect,
                                     unsigned flags) {
  if (!target->GetDocument().GetFrame() ||
      target->GetDocument().GetFrame()->LocalFrameRoot().GetOcclusionState() !=
          mojom::blink::FrameOcclusionState::kGuaranteedNotOccluded) {
    return {false, kInvalidDOMNodeId};
  }
  if (target->HasDistortingVisualEffects())
    return {false, kInvalidDOMNodeId};
  // TODO(layout-dev): This should hit-test the intersection rect, not the
  // target rect; it's not helpful to know that the portion of the target that
  // is clipped is also occluded.
  HitTestResult result(target->HitTestForOcclusion(rect));
  Node* hit_node = result.InnerNode();
  if (!hit_node || hit_node == target->GetNode())
    return {true, kInvalidDOMNodeId};
  bool should_expose_occluder_id =
      flags & IntersectionGeometry::kShouldExposeOccluderNodeId;
  // TODO(layout-dev): This IsDescendantOf tree walk could be optimized by
  // stopping when hit_node's containing LayoutBlockFlow is reached.
  if (target->IsLayoutInline()) {
    bool is_visible = hit_node->IsDescendantOf(target->GetNode());
    return {is_visible, (!is_visible && should_expose_occluder_id)
                            ? hit_node->GetDomNodeId()
                            : kInvalidDOMNodeId};
  }
  return {false, should_expose_occluder_id ? hit_node->GetDomNodeId()
                                           : kInvalidDOMNodeId};
}

// Returns the transform that maps from object's local coordinates to the
// containing view's coordinates. Note that this doesn't work if `object` has
// multiple block fragments.
gfx::Transform ObjectToViewTransform(const LayoutObject& object) {
  // Use faster GeometryMapper when possible.
  PropertyTreeStateOrAlias container_properties(
      PropertyTreeState::kUninitialized);
  const LayoutObject* property_container =
      IntersectionGeometry::CanUseGeometryMapper(object)
          ? object.GetPropertyContainer(nullptr, &container_properties)
          : nullptr;
  if (property_container) {
    gfx::Transform transform = GeometryMapper::SourceToDestinationProjection(
        container_properties.Transform(),
        object.View()->FirstFragment().LocalBorderBoxProperties().Transform());
    transform.Translate(gfx::Vector2dF(object.FirstFragment().PaintOffset()));
    return transform;
  }

  // Fall back to MapLocalToAncestor.
  TransformState transform_state(TransformState::kApplyTransformDirection);
  object.MapLocalToAncestor(nullptr, transform_state, 0);
  return transform_state.AccumulatedTransform();
}

void ScrollingContentsToBorderBoxSpace(const LayoutBox* box, gfx::RectF& rect) {
  DCHECK(box->IsScrollContainer());
  const PaintLayerScrollableArea* scrollable_area = box->GetScrollableArea();
  CHECK(scrollable_area);
  rect.Offset(-scrollable_area->ScrollPosition().OffsetFromOrigin());
}

bool ClipsSelf(const LayoutObject& object) {
  return object.HasClip() || object.HasClipPath() || object.HasMask() ||
         // For simplicity, assume all SVG children clip self (with e.g.
         // SVG mask).
         object.IsSVGChild();
}

bool ClipsContents(const LayoutObject& object) {
  // An objects that clips itself also clips contents.
  if (ClipsSelf(object)) {
    return true;
  }
  // TODO(wangxianzhu): Ideally we should ignore clippers that don't have
  // a scrollable overflow, but that caused crbug.com/41492283. Investigate.
  return object.ShouldClipOverflowAlongEitherAxis();
}

static const unsigned kConstructorFlagsMask =
    IntersectionGeometry::kShouldReportRootBounds |
    IntersectionGeometry::kShouldComputeVisibility |
    IntersectionGeometry::kShouldTrackFractionOfRoot |
    IntersectionGeometry::kForFrameViewportIntersection |
    IntersectionGeometry::kShouldConvertToCSSPixels |
    IntersectionGeometry::kUseOverflowClipEdge |
    IntersectionGeometry::kRespectFilters |
    IntersectionGeometry::kScrollAndVisibilityOnly |
    IntersectionGeometry::kShouldExposeOccluderNodeId;

}  // namespace

IntersectionGeometry::RootGeometry::RootGeometry(const LayoutObject* root,
                                                 const Vector<Length>& margin) {
  if (!root || !root->GetNode() || !root->GetNode()->isConnected() ||
      // TODO(crbug.com/1456208): Support inline root.
      !root->IsBox()) {
    return;
  }
  zoom = root->StyleRef().EffectiveZoom();
  pre_margin_local_root_rect = InitializeRootRect(root);
  UpdateMargin(margin);
  root_to_view_transform = ObjectToViewTransform(*root);
}

void IntersectionGeometry::RootGeometry::UpdateMargin(
    const Vector<Length>& margin) {
  local_root_rect = pre_margin_local_root_rect;
  ApplyMargin(local_root_rect, margin, zoom, pre_margin_local_root_rect.size());
}

bool IntersectionGeometry::RootGeometry::operator==(
    const RootGeometry& other) const {
  return zoom == other.zoom && local_root_rect == other.local_root_rect &&
         root_to_view_transform == other.root_to_view_transform;
}

const LayoutObject* IntersectionGeometry::GetExplicitRootLayoutObject(
    const Node& root_node) {
  if (!root_node.isConnected()) {
    return nullptr;
  }
  if (root_node.IsDocumentNode()) {
    return To<Document>(root_node).GetLayoutView();
  }
  return root_node.GetLayoutObject();
}

IntersectionGeometry::IntersectionGeometry(
    const Node* root_node,
    const Element& target_element,
    const Vector<Length>& root_margin,
    const Vector<float>& thresholds,
    const Vector<Length>& target_margin,
    const Vector<Length>& scroll_margin,
    unsigned flags,
    std::optional<RootGeometry>& root_geometry,
    CachedRects* cached_rects)
    : flags_(flags & kConstructorFlagsMask) {
  // Only one of root_margin or target_margin can be specified.
  DCHECK(root_margin.empty() || target_margin.empty());

  if (!root_node) {
    flags_ |= kRootIsImplicit;
  }

  RootAndTarget root_and_target(root_node, target_element,
                                !target_margin.empty(), !scroll_margin.empty());
  UpdateShouldUseCachedRects(root_and_target, cached_rects);
  if (root_and_target.relationship == RootAndTarget::kInvalid) {
    return;
  }

  if (root_geometry) {
    DCHECK(*root_geometry == RootGeometry(root_and_target.root, root_margin));
  } else {
    root_geometry.emplace(root_and_target.root, root_margin);
  }

  ComputeGeometry(*root_geometry, root_and_target, thresholds, target_margin,
                  scroll_margin, cached_rects);
}

IntersectionGeometry::RootAndTarget::RootAndTarget(
    const Node* root_node,
    const Element& target_element,
    bool has_target_margin,
    bool has_scroll_margin)
    : target(GetTargetLayoutObject(target_element)),
      root(target ? GetRootLayoutObject(root_node) : nullptr) {
  ComputeRelationship(!root_node, has_target_margin, has_scroll_margin);
}

bool IsAllowedLayoutObjectType(const LayoutObject& target) {
  return target.IsBoxModelObject() || target.IsText() || target.IsSVG();
}

// Validates the given target element and returns its LayoutObject
const LayoutObject* IntersectionGeometry::GetTargetLayoutObject(
    const Element& target_element) {
  if (!target_element.isConnected()) {
    return nullptr;
  }
  LayoutObject* target = target_element.GetLayoutObject();
  if (!target || !IsAllowedLayoutObjectType(*target)) {
    return nullptr;
  }
  // If the target is inside a locked subtree, it isn't ever visible.
  if (target->GetFrameView()->IsDisplayLocked() ||
      DisplayLockUtilities::IsInLockedSubtreeCrossingFrames(target_element))
      [[unlikely]] {
    return nullptr;
  }

  DCHECK(!target_element.GetDocument().View()->NeedsLayout());
  return target;
}

// If root_node is non-null, it is treated as the explicit root of an
// IntersectionObserver; if it is valid, its LayoutObject is returned.
//
// If root_node is null, returns the object to be used to compute intersection
// for a given target with the implicit root. Note that if the target is in
// a remote frame, the returned object is the LayoutView of the local frame
// root instead of the topmost main frame.
//
//   https://w3c.github.io/IntersectionObserver/#dom-intersectionobserver-root
const LayoutObject* IntersectionGeometry::RootAndTarget::GetRootLayoutObject(
    const Node* root_node) const {
  if (root_node) {
    return GetExplicitRootLayoutObject(*root_node);
  }
  if (const LocalFrame* frame = target->GetDocument().GetFrame()) {
    return frame->LocalFrameRoot().ContentLayoutObject();
  }
  return nullptr;
}

void IntersectionGeometry::RootAndTarget::ComputeRelationship(
    bool root_is_implicit,
    bool has_target_margin,
    bool has_scroll_margin) {
  if (!root || !target || root == target) {
    relationship = kInvalid;
    return;
  }

  if (root_is_implicit && !target->GetFrame()->IsOutermostMainFrame()) {
    relationship = kTargetInSubFrame;
    DCHECK(root->IsScrollContainer());
    DCHECK(root->IsLayoutView());
    root_scrolls_target = To<LayoutView>(root)->HasScrollableOverflow();
    if (root_scrolls_target) {
      // Check if target's ancestor container under root is fixed-position.
      // If yes, reset root_scroll_target to false.
      const LayoutObject* container = target;
      while (container->GetFrame() != root->GetFrame()) {
        container = container->GetFrame()->OwnerLayoutObject();
        if (!container) {
          relationship = kInvalid;
          return;
        }
      }
      while (true) {
        const LayoutObject* next_container = container->Container();
        if (next_container == root) {
          root_scrolls_target = !container->IsFixedPositioned();
          break;
        }
        container = next_container;
      }
    }

    if (!has_scroll_margin) {
      // When scroll margins are defined intermediate_scrollers still needs to
      // get populated.
      return;
    }
  }

  if (target->GetFrame() != root->GetFrame() && !root_is_implicit) {
    // The case of different frame with implicit root has been covered by the
    // previous condition.
    // The target and the explicit root are required to be in the same frame.
    relationship = kInvalid;
    return;
  }

  bool has_intermediate_clippers = false;
  const LayoutObject* previous_container = nullptr;
  const LayoutObject* container = target;
  bool have_crossed_frame_boundary = false;
  if (ClipsSelf(*target)) {
    has_intermediate_clippers = true;
  }
  while (container != root) {
    has_filter |=
        !have_crossed_frame_boundary && container->HasFilterInducingProperty();

    // Don't check for filters if we've already found one.
    LayoutObject::AncestorSkipInfo skip_info(root, !has_filter);
    previous_container = container;
    container = container->Container(&skip_info);
    if (!has_filter && !have_crossed_frame_boundary) {
      has_filter = skip_info.FilterSkipped();
    }

    if (skip_info.AncestorSkipped()) {
      DCHECK(!have_crossed_frame_boundary);

      // The root is not in the containing block chain of the target.
      relationship = kInvalid;
      return;
    }

    if (!container) {
      if (!root_is_implicit) {
        relationship = kInvalid;
        return;
      }

      // We need to jump up the frame tree
      DCHECK(previous_container->IsLayoutView());

      // previous_container is the layout view of the iframe.
      // OwnerLayoutObject jumps the iframe boundary.
      // owner is the iframe element node.
      auto* owner =
          previous_container->GetFrameView()->GetFrame().OwnerLayoutObject();
      if (!owner) {
        return;
      }

      container = owner;
      have_crossed_frame_boundary = true;

      // We can continue to top of loop since iframe element is not a scroller.
      continue;
    }

    if (!has_intermediate_clippers && !have_crossed_frame_boundary &&
        container != root && ClipsContents(*container)) {
      has_intermediate_clippers = true;
    }

    if (container != root && has_scroll_margin &&
        container->IsScrollContainer()) {
      intermediate_scrollers.push_back(To<LayoutBox>(container));
    }
  }

  DCHECK(previous_container);
  root_scrolls_target =
      root->IsScrollContainer() &&
      To<LayoutBox>(root)->HasScrollableOverflow() &&
      !(root->IsLayoutView() && previous_container->IsFixedPositioned());

  if (have_crossed_frame_boundary) {
    DCHECK_EQ(relationship, kTargetInSubFrame);
  } else if (has_intermediate_clippers) {
    relationship = kHasIntermediateClippers;
  } else if (root_scrolls_target) {
    relationship = kScrollableByRootOnly;
  } else {
    relationship = kNotScrollable;
  }
}

bool IntersectionGeometry::CanUseGeometryMapper(const LayoutObject& object) {
  // This checks for cases where we didn't just complete a successful lifecycle
  // update, e.g., if the frame is throttled.
  LayoutView* layout_view = object.GetDocument().GetLayoutView();
  return layout_view && !layout_view->NeedsPaintPropertyUpdate() &&
         !layout_view->DescendantNeedsPaintPropertyUpdate();
}

void IntersectionGeometry::UpdateShouldUseCachedRects(
    const RootAndTarget& root_and_target,
    CachedRects* cached_rects) {
  if (!cached_rects || !cached_rects->valid) {
    return;
  }

  cached_rects->valid = false;

  if (root_and_target.relationship == RootAndTarget::kInvalid) {
    return;
  }

  if (!root_and_target.intermediate_scrollers.empty()) {
    // This happens when there are scroll margins. We can't use cached rects
    // because we need to call ApplyClip for each scroller to apply the
    // scroll margins.
    return;
  }

  if (!(flags_ & kScrollAndVisibilityOnly)) {
    return;
  }
  // Cached rects can only be used if there are no scrollable objects in the
  // hierarchy between target and root (a scrollable root is ok). The reason
  // is that a scroll change in an intermediate scroller would change the
  // intersection geometry, but we intentionally don't invalidate cached
  // rects and schedule intersection update to enable the minimul-scroll-
  // delta-to-update optimization.
  if (root_and_target.relationship != RootAndTarget::kNotScrollable &&
      root_and_target.relationship != RootAndTarget::kScrollableByRootOnly) {
    return;
  }

  flags_ |= kShouldUseCachedRects;
}

void IntersectionGeometry::ComputeGeometry(const RootGeometry& root_geometry,
                                           const RootAndTarget& root_and_target,
                                           const Vector<float>& thresholds,
                                           const Vector<Length>& target_margin,
                                           const Vector<Length>& scroll_margin,
                                           CachedRects* cached_rects) {
  CHECK_GE(thresholds.size(), 1u);
  DCHECK(cached_rects || !ShouldUseCachedRects());
  flags_ |= kDidComputeGeometry;

  const LayoutObject* root = root_and_target.root;
  const LayoutObject* target = root_and_target.target;
  CHECK(root);
  CHECK(target);

  // Initially:
  //   target_rect_ is in target's coordinate system
  //   root_rect_ is in root's coordinate system
  //   The coordinate system for unclipped_intersection_rect_ depends on whether
  //       or not we can use previously cached geometry...
  bool pre_margin_target_rect_is_empty;
  if (ShouldUseCachedRects()) {
    target_rect_ = cached_rects->local_target_rect;
    pre_margin_target_rect_is_empty =
        cached_rects->pre_margin_target_rect_is_empty;

    // The cached intersection rect has already been mapped/clipped up to the
    // root, except that the root's scroll offset and overflow clip have not
    // been applied.
    unclipped_intersection_rect_ =
        cached_rects->unscrolled_unclipped_intersection_rect;
  } else {
    target_rect_ = InitializeTargetRect(target, flags_);
    pre_margin_target_rect_is_empty = target_rect_.IsEmpty();
    ApplyMargin(target_rect_, target_margin, root_geometry.zoom,
                root_geometry.pre_margin_local_root_rect.size());

    // We have to map/clip target_rect_ up to the root, so we begin with the
    // intersection rect in target's coordinate system. After ClipToRoot, it
    // will be in root's coordinate system.
    unclipped_intersection_rect_ = target_rect_;
  }
  if (cached_rects) {
    cached_rects->local_target_rect = target_rect_;
    cached_rects->pre_margin_target_rect_is_empty =
        pre_margin_target_rect_is_empty;
  }
  root_rect_ = root_geometry.local_root_rect;

  bool does_intersect =
      ClipToRoot(root_and_target, root_rect_, unclipped_intersection_rect_,
                 intersection_rect_, scroll_margin, cached_rects);

  gfx::Transform target_to_view_transform = ObjectToViewTransform(*target);
  target_rect_ = target_to_view_transform.MapRect(target_rect_);

  if (does_intersect) {
    gfx::RectF unclipped_intersection_rect;
    if (RootIsImplicit()) {
      // Generate matrix to transform from the space of the implicit root to
      // the absolute coordinates of the target document.
      TransformState implicit_root_to_target_document_transform(
          TransformState::kUnapplyInverseTransformDirection);
      target->View()->MapAncestorToLocal(
          nullptr, implicit_root_to_target_document_transform,
          kTraverseDocumentBoundaries | kApplyRemoteMainFrameTransform);
      gfx::Transform matrix =
          implicit_root_to_target_document_transform.AccumulatedTransform()
              .InverseOrIdentity();
      intersection_rect_ =
          matrix.ProjectQuad(gfx::QuadF(intersection_rect_)).BoundingBox();
      unclipped_intersection_rect =
          matrix.ProjectQuad(gfx::QuadF(unclipped_intersection_rect_))
              .BoundingBox();
    } else {
      // `intersection_rect` is in root's coordinate system; map it up to
      // absolute coordinates for target's containing document (which is the
      // same as root's document).
      intersection_rect_ =
          root_geometry.root_to_view_transform.MapRect(intersection_rect_);
      unclipped_intersection_rect =
          root_geometry.root_to_view_transform.MapRect(
              unclipped_intersection_rect);
    }
    unclipped_intersection_rect_ = unclipped_intersection_rect;
  } else {
    intersection_rect_ = gfx::RectF();
  }
  // Map root_rect_ from root's coordinate system to absolute coordinates.
  root_rect_ =
      root_geometry.root_to_view_transform.MapRect(gfx::RectF(root_rect_));

  // Some corner cases for threshold index:
  //   - If target rect is zero area, because it has zero width and/or zero
  //     height,
  //     only two states are recognized:
  //     - 0 means not intersecting.
  //     - 1 means intersecting.
  //     No other threshold crossings are possible.
  //   - Otherwise:
  //     - If root and target do not intersect, the threshold index is 0.

  //     - If root and target intersect but the intersection has zero-area
  //       (i.e., they have a coincident edge or corner), we consider the
  //       intersection to have "crossed" a zero threshold, but not crossed
  //       any non-zero threshold.

  if (does_intersect) {
    const gfx::RectF& comparison_rect =
        ShouldTrackFractionOfRoot() ? root_rect_ : target_rect_;
    // Note that if we are checking whether target is empty, we have to consider
    // the fact that we might have padded the rect with a target margin. If we
    // did, `pre_margin_target_rect_is_empty` would be true. Use this
    // information to force the rect to be empty for the purposes of this
    // computation. Note that it could also be the case that the rect started as
    // non-empty and was transformed to be empty. In this case, we rely on
    // target_rect_.IsEmpty() to be true, so we need to check the rect itself as
    // well.
    // In the fraction of root case, we can just check the comparison rect.
    bool empty_override =
        !ShouldTrackFractionOfRoot() && pre_margin_target_rect_is_empty;
    if (comparison_rect.IsEmpty() || empty_override) {
      intersection_ratio_ = 1;
    } else {
      const gfx::SizeF& intersection_size = intersection_rect_.size();
      const float intersection_area = intersection_size.GetArea();
      const gfx::SizeF& comparison_size = comparison_rect.size();
      const float area_of_interest = comparison_size.GetArea();
      intersection_ratio_ = std::min(intersection_area / area_of_interest, 1.f);
    }
    threshold_index_ =
        FirstThresholdGreaterThan(intersection_ratio_, thresholds);
  } else {
    intersection_ratio_ = 0;
    threshold_index_ = 0;
  }
  if (IsIntersecting() && ShouldComputeVisibility()) {
    auto visiblity_info = ComputeVisibilityInfo(
        target, PhysicalRect::FastAndLossyFromRectF(target_rect_), flags_);
    occluder_node_id_ = visiblity_info.occluder_node_id;
    if (visiblity_info.is_visible) {
      flags_ |= kIsVisible;
    }
  } else {
    occluder_node_id_ = kInvalidDOMNodeId;
  }

  if (cached_rects) {
    cached_rects->min_scroll_delta_to_update = ComputeMinScrollDeltaToUpdate(
        root_and_target, target_to_view_transform,
        root_geometry.root_to_view_transform, thresholds, scroll_margin);
    cached_rects->valid = true;
  }

  // This must be the last step after all calculations in zoomed coordinates.
  if (flags_ & kShouldConvertToCSSPixels) {
    AdjustForAbsoluteZoom::AdjustRectMaybeExcludingCSSZoom(target_rect_,
                                                           *target);
    AdjustForAbsoluteZoom::AdjustRectMaybeExcludingCSSZoom(intersection_rect_,
                                                           *target);
    AdjustForAbsoluteZoom::AdjustRectMaybeExcludingCSSZoom(root_rect_, *root);
  }
}

bool IntersectionGeometry::ClipToRoot(const RootAndTarget& root_and_target,
                                      const gfx::RectF& root_rect,
                                      gfx::RectF& unclipped_intersection_rect,
                                      gfx::RectF& intersection_rect,
                                      const Vector<Length>& scroll_margin,
                                      CachedRects* cached_rects) {
  const LayoutObject* root = root_and_target.root;
  // TODO(crbug.com/1456208): Support inline root.
  if (!root->IsBox()) {
    return false;
  }

  const LayoutObject* target = root_and_target.target;

  const LayoutBox* local_ancestor = nullptr;

  bool ignore_local_clip_path = false;
  if (!scroll_margin.empty()) {
    // Apply clip and scroll margin for each intermediate scroller.
    for (const LayoutBox* scroller : root_and_target.intermediate_scrollers) {
      gfx::RectF scroller_rect =
          gfx::RectF(scroller->OverflowClipRect(PhysicalOffset()));
      if (std::optional<gfx::RectF> clip_path_box =
              ClipPathClipper::LocalClipPathBoundingBox(*scroller)) {
        scroller_rect.Intersect(*clip_path_box);
      }

      local_ancestor = To<LayoutBox>(scroller);
      if (!ApplyClip(target, local_ancestor, scroller, scroller_rect,
                     unclipped_intersection_rect, intersection_rect,
                     scroll_margin, ignore_local_clip_path,
                     /*root_scrolls_target=*/true, cached_rects)) {
        return false;
      }

      unclipped_intersection_rect = intersection_rect;
      target = scroller;
      // We have already applied clip-path on scroller (now target) above, so
      // we don't need to apply clip-path on target in the next ApplyClip().
      ignore_local_clip_path = true;
    }
  }

  // Map and clip rect into root element coordinates.
  if (!RootIsImplicit() ||
      root->GetDocument().GetFrame()->IsOutermostMainFrame()) {
    local_ancestor = To<LayoutBox>(root);
  }

  return ApplyClip(target, local_ancestor, root_and_target.root, root_rect,
                   unclipped_intersection_rect, intersection_rect,
                   scroll_margin, ignore_local_clip_path,
                   root_and_target.root_scrolls_target, cached_rects);
}

bool IntersectionGeometry::ApplyClip(const LayoutObject* target,
                                     const LayoutBox* local_ancestor,
                                     const LayoutObject* root,
                                     const gfx::RectF& root_rect,
                                     gfx::RectF& unclipped_intersection_rect,
                                     gfx::RectF& intersection_rect,
                                     const Vector<Length>& scroll_margin,
                                     bool ignore_local_clip_path,
                                     bool root_scrolls_target,
                                     CachedRects* cached_rects) {
  unsigned flags = kDefaultVisualRectFlags | kEdgeInclusive |
                   kDontApplyMainFrameOverflowClip;
  if (!ShouldRespectFilters()) {
    flags |= kIgnoreFilters;
  }
  if (CanUseGeometryMapper(*target)) {
    flags |= kUseGeometryMapper;
  }
  if (ignore_local_clip_path) {
    flags |= kIgnoreLocalClipPath;
  }

  bool does_intersect = false;

  if (ShouldUseCachedRects()) {
    does_intersect = cached_rects->does_intersect;
  } else {
    does_intersect = target->MapToVisualRectInAncestorSpace(
        local_ancestor, unclipped_intersection_rect,
        static_cast<VisualRectFlags>(flags));
    if (local_ancestor && local_ancestor->IsScrollContainer() &&
        !root_scrolls_target) {
      // Convert the rect from the scrolling contents space to the border box
      // space, so that we can use cached rects and avoid update on scroll of
      // root.
      ScrollingContentsToBorderBoxSpace(local_ancestor,
                                        unclipped_intersection_rect);
    }
  }
  if (cached_rects) {
    cached_rects->unscrolled_unclipped_intersection_rect =
        unclipped_intersection_rect;
    cached_rects->does_intersect = does_intersect;
  }

  intersection_rect = gfx::RectF();

  // If the target intersects with the unclipped root, calculate the clipped
  // intersection.
  if (does_intersect) {
    if (local_ancestor) {
      if (root_scrolls_target) {
        ScrollingContentsToBorderBoxSpace(local_ancestor,
                                          unclipped_intersection_rect);
      } else {
        // In case the ancestor in an SVG element with a viewbox property
        // we need to convert the child's coordinates to the SVG coordinates
        if (auto* properties =
               
"""


```