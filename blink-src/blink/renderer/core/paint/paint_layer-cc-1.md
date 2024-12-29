Response:
The user wants to understand the functionality of the provided C++ code snippet from `blink/renderer/core/paint/paint_layer.cc`. This is the second part of a three-part code section. The request asks for:

1. **Functionality Summary:** A high-level overview of what the code does.
2. **Relation to Web Technologies:**  How this code interacts with JavaScript, HTML, and CSS.
3. **Logical Reasoning:** Explanation using hypothetical inputs and outputs.
4. **Common Usage Errors:** Scenarios where incorrect usage might occur (from a developer's perspective).
5. **User Action to Reach Here:**  A sequence of user interactions that might lead to this code being executed during debugging.
6. **Concise Summary of Part 2:** A brief recap of the functionality in this specific code portion.

**Mental Model:**

The code heavily revolves around hit testing and fragment management within the rendering engine. `PaintLayer` objects represent visual layers in the rendering tree. The core tasks involve:

* **Fragment Collection:**  Breaking down layers into fragments, particularly relevant for elements that span across multiple pages or columns.
* **Hit Testing:** Determining if a given point (representing a user interaction like a click) falls within the bounds of a `PaintLayer` or its fragments. This involves handling transformations, clipping, and z-ordering.

**Plan:**

1. **Summarize Functionality of Part 2:** Focus on the `CollectFragments`, `HitTest`, and related `HitTestLayer` functions.
2. **Connect to Web Technologies:** Explain how fragmenting and hit testing are related to CSS (e.g., `column-count`, `break-inside`), and how JavaScript events rely on correct hit testing.
3. **Develop Hypothetical Scenarios:** Create simple examples illustrating fragment collection and hit testing with transformations.
4. **Identify Potential Errors:** Think about scenarios where developers might incorrectly style elements, leading to unexpected hit-testing behavior.
5. **Describe User Actions:** Outline a step-by-step user interaction that would trigger hit testing.
6. **Refine and Structure:** Organize the information clearly with headings and bullet points.
```
这是目录为blink/renderer/core/paint/paint_layer.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

基于提供的代码片段，这部分 `PaintLayer::cc` 代码的主要功能集中在 **管理和收集 PaintLayer 的片段信息** 以及 **执行 Hit Testing (点击测试)**。

**功能列举:**

1. **收集 PaintLayer 的片段 (Fragments):**
   - `AppendSingleFragmentForHitTesting`:  为命中测试添加单个片段。
   - `GetLayoutBoxWithBlockFragments`: 获取包含块级片段的 LayoutBox。
   - `CollectFragments`: 核心函数，用于收集 PaintLayer 的所有可见片段。这考虑到了布局对象是否可以遍历物理片段 (例如，多列布局或分页)，并根据父层的片段信息进行过滤。
   - 这些函数用于将一个可能跨越多个物理片段的逻辑 PaintLayer 分解成可以独立进行绘制和命中测试的单元。

2. **执行 Hit Testing (点击测试):**
   - `HitTestRecursionData`:  一个结构体，用于存储命中测试的递归数据，例如测试矩形、位置等。
   - `HitTest`:  入口函数，用于对 PaintLayer 及其子层执行命中测试。它会检查布局是否已更新，并调用 `HitTestLayer` 进行递归测试。
   - `HitTestLayer`:  核心递归函数，负责在当前 PaintLayer 及其子层中进行命中测试。它会考虑变换、裁剪、z-index 等因素。
   - `ComputeZOffset`: 计算变换状态下点的 z 偏移，用于处理 3D 变换的命中测试。
   - `CreateLocalTransformState`: 创建局部变换状态，用于在命中测试中考虑变换的影响。
   - `IsHitCandidateForDepthOrder`: 判断一个层是否是基于深度顺序的命中候选者。
   - `IsHitCandidateForStopNode`: 判断一个布局对象是否是命中测试的停止节点。
   - `HitTestChildren`:  递归地对子 PaintLayer 进行命中测试。
   - `HitTestForegroundForFragments`: 对片段的前景部分进行命中测试。
   - `HitTestFragmentsWithPhase`: 对片段的特定阶段 (例如背景、前景) 进行命中测试。
   - `HitTestTransformedLayerInFragments`: 处理带有变换的 PaintLayer 的命中测试，需要遍历其片段。
   - `HitTestLayerByApplyingTransform`:  对应用了变换的 PaintLayer 进行命中测试。
   - `HitTestFragmentWithPhase`: 对单个物理片段的特定阶段进行命中测试。

**与 JavaScript, HTML, CSS 的关系及举例:**

* **HTML:**  HTML 结构创建了布局对象树，而 `PaintLayer` 是基于这个布局对象树构建的。每个 HTML 元素最终会对应一个或多个 PaintLayer。
    * **例子:**  一个简单的 `<div>` 元素会创建一个 PaintLayer。一个包含了文本和其他子元素的 `<div>` 可能对应一个包含多个子 PaintLayer 的父 PaintLayer。

* **CSS:** CSS 样式决定了 PaintLayer 的属性，例如位置、大小、变换、层叠顺序 (z-index)、裁剪等，这些属性直接影响了片段的生成和命中测试的逻辑。
    * **例子:**
        * `transform: translate(10px, 20px);`:  `CreateLocalTransformState` 和相关的命中测试函数会考虑这个变换，确保点击位置经过反向变换后才能正确命中元素。
        * `overflow: hidden;`:  `ClipRectsContext` 和 `Clipper().CalculateRects` 会计算裁剪矩形，`HitTestLayer` 会根据这些裁剪矩形判断点击是否在可见区域内。
        * `column-count: 2;`:  会导致 LayoutBox 产生多个物理片段，`CollectFragments` 会收集这些片段，`HitTestFragmentsWithPhase` 需要遍历这些片段进行命中测试。
        * `z-index: 10;`:  `HitTestChildren` 会根据 z-index 的顺序遍历子 PaintLayer，确保较高 z-index 的层优先被命中。

* **JavaScript:** JavaScript 通常通过事件监听器来响应用户的交互，例如 `click` 事件。当用户点击屏幕时，浏览器引擎会执行命中测试来确定哪个 HTML 元素被点击了，这个过程就涉及到 `PaintLayer` 及其命中测试的相关代码。
    * **例子:**
        ```javascript
        document.getElementById('myButton').addEventListener('click', function() {
          console.log('Button clicked!');
        });
        ```
        当用户点击 ID 为 `myButton` 的元素时，浏览器会执行命中测试，最终确定点击事件应该分发到与该按钮关联的 `PaintLayer` 对应的 HTML 元素。

**逻辑推理 (假设输入与输出):**

**场景:** 一个带有 `transform: translate(50px, 50px)` 样式的 `<div>` 元素。用户点击屏幕上的某个点。

**假设输入:**
* `PaintLayer` 对象对应于该 `<div>` 元素。
* `HitTestLocation` 对象表示用户点击的屏幕坐标，例如 `(100, 100)`。
* `HitTestRequest` 对象包含命中测试的类型 (例如，鼠标点击)。

**逻辑推理过程:**

1. `HitTest` 函数被调用，接收 `HitTestLocation` 和 `HitTestRequest`。
2. `HitTestLayer` 函数被调用，开始递归地检查当前 `PaintLayer`。
3. 由于存在 `transform` 属性，`HitTestLayer` 可能会调用 `HitTestTransformedLayerInFragments`。
4. `CreateLocalTransformState` 被调用，创建一个包含反向变换的变换状态。
5. `HitTestLayerByApplyingTransform` 被调用，将点击坐标 `(100, 100)` 通过反向变换转换为 `<div>` 元素的局部坐标。例如，如果变换是 `translate(50px, 50px)`, 那么局部坐标可能是 `(50, 50)`。
6. `HitTestLayer` 会检查变换后的点击坐标是否在 `<div>` 元素的边界内。

**假设输出:**

* 如果变换后的点击坐标在 `<div>` 元素的边界内，`HitTestLayer` 返回指向该 `PaintLayer` 的指针，表示命中。
* 否则，`HitTestLayer` 返回 `nullptr`，表示未命中。

**用户或编程常见的使用错误:**

1. **CSS 变换导致的命中区域不准确:** 开发者可能使用了复杂的 CSS 变换，但没有正确理解变换对命中测试的影响，导致点击事件无法正确触发。
    * **例子:**  一个元素旋转后，其视觉边界可能与实际的命中边界不一致。

2. **`z-index` 导致的遮挡问题:**  开发者可能没有正确设置 `z-index`，导致某个元素被其他元素遮挡，即使点击了该元素的可视区域，但由于命中测试优先命中了上层的元素，导致事件无法传递到下层元素。

3. **`overflow: hidden` 裁剪导致的不可点击区域:** 开发者使用 `overflow: hidden` 隐藏了元素的部分内容，但仍然希望能够点击被隐藏区域内的元素。这是不可能的，因为裁剪会直接影响命中测试的范围。

4. **使用绝对定位和变换时坐标计算错误:**  开发者在 JavaScript 中手动计算元素的位置或碰撞检测时，可能没有考虑到 CSS 变换的影响，导致计算出的坐标与渲染引擎的命中测试逻辑不一致。

**用户操作如何一步步的到达这里 (调试线索):**

1. **用户在浏览器中打开一个网页。**
2. **用户将鼠标移动到网页上的一个元素上。** (可能触发 hover 效果，也可能只是简单的移动)
3. **用户点击鼠标左键。**
4. **浏览器接收到鼠标点击事件。**
5. **浏览器引擎需要确定哪个 HTML 元素被点击了。** 这会触发命中测试过程。
6. **命中测试从根 `PaintLayer` 开始，递归地向下遍历 `PaintLayer` 树。**
7. **在遍历过程中，会调用 `HitTest` 和 `HitTestLayer` 等函数。**
8. **如果被点击的元素具有 CSS 变换，则会调用 `CreateLocalTransformState` 和 `HitTestLayerByApplyingTransform` 来处理变换。**
9. **最终，命中测试会确定被点击的 `PaintLayer`，并将其关联的 HTML 元素作为事件的目标。**

**作为调试线索:**  如果在调试过程中，用户发现点击某个元素没有响应，或者响应了错误的元素，那么可以断点到 `HitTestLayer` 或 `HitTestTransformedLayerInFragments` 等函数，查看命中测试的坐标、变换矩阵、裁剪矩形等信息，以定位问题所在。

**归纳一下它的功能 (第2部分):**

这部分 `PaintLayer::cc` 代码主要负责 **管理 PaintLayer 的片段信息，以便进行更精细化的绘制和命中测试，并且实现了核心的命中测试逻辑，能够考虑到 CSS 变换、裁剪、层叠顺序等因素，最终确定用户交互的目标元素。**  它连接了渲染引擎的内部表示 (PaintLayer) 和用户的交互行为 (鼠标点击)，是浏览器实现事件处理的关键组成部分。

Prompt: 
```
这是目录为blink/renderer/core/paint/paint_layer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
ment* container_fragment,
    ShouldRespectOverflowClipType respect_overflow_clip) const {
  PaintLayerFragment fragment;
  if (container_fragment) {
    fragment = *container_fragment;
  } else {
    fragment.fragment_data = &GetLayoutObject().FirstFragment();
    if (GetLayoutObject().CanTraversePhysicalFragments()) {
      // Make sure that we actually traverse the fragment tree, by providing a
      // physical fragment. Otherwise we'd fall back to LayoutObject traversal.
      if (const auto* layout_box = GetLayoutBox())
        fragment.physical_fragment = layout_box->GetPhysicalFragment(0);
    }
    fragment.fragment_idx = 0;
  }

  ClipRectsContext clip_rects_context(this, fragment.fragment_data,
                                      kExcludeOverlayScrollbarSizeForHitTesting,
                                      respect_overflow_clip);
  Clipper().CalculateRects(clip_rects_context, *fragment.fragment_data,
                           fragment.layer_offset, fragment.background_rect,
                           fragment.foreground_rect);

  fragments.push_back(fragment);
}

const LayoutBox* PaintLayer::GetLayoutBoxWithBlockFragments() const {
  const LayoutBox* layout_box = GetLayoutBox();
  if (!layout_box || !layout_box->CanTraversePhysicalFragments()) {
    return nullptr;
  }
  DCHECK(!layout_box->IsFragmentLessBox());
  return layout_box;
}

void PaintLayer::CollectFragments(
    PaintLayerFragments& fragments,
    const PaintLayer* root_layer,
    ShouldRespectOverflowClipType respect_overflow_clip,
    const FragmentData* root_fragment_arg) const {
  PaintLayerFragment fragment;
  const auto& first_root_fragment_data =
      root_layer->GetLayoutObject().FirstFragment();

  const LayoutBox* layout_box_with_fragments = GetLayoutBoxWithBlockFragments();

  // The NG hit-testing code guards against painting multiple fragments for
  // content that doesn't support it, but the legacy hit-testing code has no
  // such guards.
  // TODO(crbug.com/1229581): Remove this when everything is handled by NG.
  bool multiple_fragments_allowed =
      layout_box_with_fragments || CanPaintMultipleFragments(GetLayoutObject());

  // The inherited offset_from_root does not include any pagination offsets.
  // In the presence of fragmentation, we cannot use it.
  wtf_size_t physical_fragment_idx = 0u;
  for (FragmentDataIterator iterator(GetLayoutObject()); !iterator.IsDone();
       ++iterator, physical_fragment_idx++) {
    const FragmentData* fragment_data = iterator.GetFragmentData();
    const FragmentData* root_fragment_data = nullptr;
    if (root_fragment_arg) {
      DCHECK(this != root_layer);
      if (!root_fragment_arg->ContentsProperties().Transform().IsAncestorOf(
              fragment_data->LocalBorderBoxProperties().Transform())) {
        // We only want to collect fragments that are descendants of
        // |root_fragment_arg|.
        continue;
      }
      root_fragment_data = root_fragment_arg;
    } else if (root_layer == this) {
      root_fragment_data = fragment_data;
    } else {
      root_fragment_data = &first_root_fragment_data;
    }

    ClipRectsContext clip_rects_context(
        root_layer, root_fragment_data,
        kExcludeOverlayScrollbarSizeForHitTesting, respect_overflow_clip,
        PhysicalOffset());

    Clipper().CalculateRects(clip_rects_context, *fragment_data,
                             fragment.layer_offset, fragment.background_rect,
                             fragment.foreground_rect);

    fragment.fragment_data = fragment_data;

    if (layout_box_with_fragments) {
      fragment.physical_fragment =
          layout_box_with_fragments->GetPhysicalFragment(physical_fragment_idx);
      DCHECK(fragment.physical_fragment);
    }

    fragment.fragment_idx = physical_fragment_idx;

    fragments.push_back(fragment);

    if (!multiple_fragments_allowed)
      break;
  }
}

PaintLayer::HitTestRecursionData::HitTestRecursionData(
    const PhysicalRect& rect_arg,
    const HitTestLocation& location_arg,
    const HitTestLocation& original_location_arg)
    : rect(rect_arg),
      location(location_arg),
      original_location(original_location_arg),
      intersects_location(location_arg.Intersects(rect_arg)) {}

bool PaintLayer::HitTest(const HitTestLocation& hit_test_location,
                         HitTestResult& result,
                         const PhysicalRect& hit_test_area) {
  // The root PaintLayer of HitTest must contain all descendants.
  DCHECK(GetLayoutObject().CanContainFixedPositionObjects());
  DCHECK(GetLayoutObject().CanContainAbsolutePositionObjects());

  // LayoutView should make sure to update layout before entering hit testing
  DCHECK(!GetLayoutObject().GetFrame()->View()->LayoutPending());
  DCHECK(!GetLayoutObject().GetDocument().GetLayoutView()->NeedsLayout());

  const HitTestRequest& request = result.GetHitTestRequest();

  HitTestRecursionData recursion_data(hit_test_area, hit_test_location,
                                      hit_test_location);
  PaintLayer* inside_layer = HitTestLayer(*this, /*container_fragment*/ nullptr,
                                          result, recursion_data);
  if (!inside_layer && IsRootLayer()) {
    bool fallback = false;
    // If we didn't hit any layers but are still inside the document
    // bounds, then we should fallback to hitting the document.
    // For rect-based hit test, we do the fallback only when the hit-rect
    // is totally within the document bounds.
    if (hit_test_area.Contains(hit_test_location.BoundingBox())) {
      fallback = true;

      // Mouse dragging outside the main document should also be
      // delivered to the document.
      // TODO(miletus): Capture behavior inconsistent with iframes
      // crbug.com/522109.
      // TODO(majidvp): This should apply more consistently across different
      // event types and we should not use RequestType for it. Perhaps best for
      // it to be done at a higher level. See http://crbug.com/505825
    } else if ((request.Active() || request.Release()) &&
               !request.IsChildFrameHitTest()) {
      fallback = true;
    }
    if (fallback) {
      GetLayoutObject().UpdateHitTestResult(result, hit_test_location.Point());
      inside_layer = this;

      // Don't cache this result since it really wasn't a true hit.
      result.SetCacheable(false);
    }
  }

  // Now determine if the result is inside an anchor - if the urlElement isn't
  // already set.
  Node* node = result.InnerNode();
  if (node && !result.URLElement())
    result.SetURLElement(node->EnclosingLinkEventParentOrSelf());

  // Now return whether we were inside this layer (this will always be true for
  // the root layer).
  return inside_layer;
}

Node* PaintLayer::EnclosingNode() const {
  for (LayoutObject* r = &GetLayoutObject(); r; r = r->Parent()) {
    if (Node* e = r->GetNode())
      return e;
  }
  NOTREACHED();
}

bool PaintLayer::IsInTopOrViewTransitionLayer() const {
  return GetLayoutObject().IsInTopOrViewTransitionLayer();
}

// Compute the z-offset of the point in the transformState.
// This is effectively projecting a ray normal to the plane of ancestor, finding
// where that ray intersects target, and computing the z delta between those two
// points.
static double ComputeZOffset(const HitTestingTransformState& transform_state) {
  // We got an affine transform, so no z-offset
  if (transform_state.AccumulatedTransform().Is2dTransform())
    return 0;

  // Flatten the point into the target plane
  gfx::PointF target_point = transform_state.MappedPoint();

  // Now map the point back through the transform, which computes Z.
  gfx::Point3F backmapped_point =
      transform_state.AccumulatedTransform().MapPoint(
          gfx::Point3F(target_point));
  return backmapped_point.z();
}

HitTestingTransformState PaintLayer::CreateLocalTransformState(
    const PaintLayer& transform_container,
    const FragmentData& transform_container_fragment,
    const FragmentData& local_fragment,
    const HitTestRecursionData& recursion_data,
    const HitTestingTransformState* container_transform_state) const {
  // If we're already computing transform state, then it's relative to the
  // container (which we know is non-null).
  // If this is the first time we need to make transform state, then base it
  // off of hitTestLocation, which is relative to rootLayer.
  HitTestingTransformState transform_state =
      container_transform_state
          ? *container_transform_state
          : HitTestingTransformState(
                recursion_data.location.TransformedPoint(),
                recursion_data.location.TransformedRect(),
                gfx::QuadF(gfx::RectF(recursion_data.rect)));

  if (&transform_container == this) {
    DCHECK(!container_transform_state);
    return transform_state;
  }

  if (container_transform_state &&
      (!transform_container.Preserves3D() ||
       &transform_container.GetLayoutObject() !=
           GetLayoutObject().NearestAncestorForElement())) {
    // The transform container layer doesn't preserve 3d, or its preserve-3d
    // doesn't apply to this layer because our element is not a child of the
    // transform container layer's element.
    transform_state.Flatten();
  }

  DCHECK_NE(&transform_container_fragment, &local_fragment);

  const auto* container_transform =
      &transform_container_fragment.LocalBorderBoxProperties().Transform();
  if (const auto* properties = transform_container_fragment.PaintProperties()) {
    if (const auto* perspective = properties->Perspective()) {
      transform_state.ApplyTransform(*perspective);
      container_transform = perspective;
    }
  }

  transform_state.Translate(
      gfx::Vector2dF(-transform_container_fragment.PaintOffset()));
  transform_state.ApplyTransform(GeometryMapper::SourceToDestinationProjection(
      local_fragment.PreTransform(), *container_transform));
  transform_state.Translate(gfx::Vector2dF(local_fragment.PaintOffset()));

  if (const auto* properties = local_fragment.PaintProperties()) {
    for (const TransformPaintPropertyNode* transform :
         properties->AllCSSTransformPropertiesOutsideToInside()) {
      if (transform)
        transform_state.ApplyTransform(*transform);
    }
  }

  return transform_state;
}

static bool IsHitCandidateForDepthOrder(
    const PaintLayer* hit_layer,
    bool can_depth_sort,
    double* z_offset,
    const HitTestingTransformState* transform_state) {
  if (!hit_layer)
    return false;

  // The hit layer is depth-sorting with other layers, so just say that it was
  // hit.
  if (can_depth_sort)
    return true;

  // We need to look at z-depth to decide if this layer was hit.
  //
  // See comment in PaintLayer::HitTestLayer regarding SVG
  // foreignObject; if it weren't for that case we could test z_offset
  // and then DCHECK(transform_state) inside of it.
  DCHECK(!z_offset || transform_state ||
         hit_layer->GetLayoutObject().IsSVGForeignObject());
  if (z_offset && transform_state) {
    // This is actually computing our z, but that's OK because the hitLayer is
    // coplanar with us.
    double child_z_offset = ComputeZOffset(*transform_state);
    if (child_z_offset > *z_offset) {
      *z_offset = child_z_offset;
      return true;
    }
    return false;
  }

  return true;
}

// Calling IsDescendantOf is sad (slow), but it's the only way to tell
// whether a hit test candidate is a descendant of the stop node.
static bool IsHitCandidateForStopNode(const LayoutObject& candidate,
                                      const LayoutObject* stop_node) {
  return !stop_node || (&candidate == stop_node) ||
         !candidate.IsDescendantOf(stop_node);
}

// recursion_data.location and rect are relative to |transform_container|.
// A 'flattening' layer is one preserves3D() == false.
// transform_state.AccumulatedTransform() holds the transform from the
// containing flattening layer.
// transform_state.last_planar_point_ is the hit test location in the plane of
// the containing flattening layer.
// transform_state.last_planar_quad_ is the hit test rect as a quad in the
// plane of the containing flattening layer.
//
// If z_offset is non-null (which indicates that the caller wants z offset
// information), *z_offset on return is the z offset of the hit point relative
// to the containing flattening layer.
//
// If |container_fragment| is null, we'll hit test all fragments. Otherwise it
// points to a fragment of |transform_container|, and descendants should hit
// test their fragments that are descendants of |container_fragment|.
PaintLayer* PaintLayer::HitTestLayer(
    const PaintLayer& transform_container,
    const PaintLayerFragment* container_fragment,
    HitTestResult& result,
    const HitTestRecursionData& recursion_data,
    bool applied_transform,
    HitTestingTransformState* container_transform_state,
    double* z_offset,
    bool overflow_controls_only) {
  const FragmentData* container_fragment_data =
      container_fragment ? container_fragment->fragment_data : nullptr;
  const auto& container_layout_object = transform_container.GetLayoutObject();
  DCHECK(container_layout_object.CanContainFixedPositionObjects());
  DCHECK(container_layout_object.CanContainAbsolutePositionObjects());

  const LayoutObject& layout_object = GetLayoutObject();
  DCHECK_GE(layout_object.GetDocument().Lifecycle().GetState(),
            DocumentLifecycle::kPrePaintClean);

  if (layout_object.NeedsLayout() &&
      !layout_object.ChildLayoutBlockedByDisplayLock()) [[unlikely]] {
    // Skip if we need layout. This should never happen. See crbug.com/1423308
    // and crbug.com/330051489.
    return nullptr;
  }

  if (layout_object.IsFragmentLessBox()) {
    return nullptr;
  }

  if (!IsSelfPaintingLayer() && !HasSelfPaintingLayerDescendant())
    return nullptr;

  if ((result.GetHitTestRequest().GetType() &
       HitTestRequest::kIgnoreZeroOpacityObjects) &&
      !layout_object.HasNonZeroEffectiveOpacity()) {
    return nullptr;
  }

  std::optional<CheckAncestorPositionVisibilityScope>
      check_position_visibility_scope;
  if (InvisibleForPositionVisibility() ||
      HasAncestorInvisibleForPositionVisibility()) {
    return nullptr;
  }
  if (GetLayoutObject().IsStackingContext()) {
    check_position_visibility_scope.emplace(*this);
  }

  // TODO(vmpstr): We need to add a simple document flag which says whether
  // there is an ongoing transition, since this may be too heavy of a check for
  // each hit test.
  if (auto* transition =
          ViewTransitionUtils::GetTransition(layout_object.GetDocument())) {
    // This means that the contents of the object are drawn elsewhere.
    if (transition->IsRepresentedViaPseudoElements(layout_object))
      return nullptr;
  }

  ShouldRespectOverflowClipType clip_behavior = kRespectOverflowClip;
  if (result.GetHitTestRequest().IgnoreClipping())
    clip_behavior = kIgnoreOverflowClip;

  // For the global root scroller, hit test the layout viewport scrollbars
  // first, as they are visually presented on top of the content.
  if (layout_object.IsGlobalRootScroller()) {
    // There are a number of early outs below that don't apply to the the
    // global root scroller.
    DCHECK(!Transform());
    DCHECK(!Preserves3D());
    DCHECK(!layout_object.HasClipPath());
    if (scrollable_area_) {
      gfx::Point point = scrollable_area_->ConvertFromRootFrameToVisualViewport(
          ToRoundedPoint(recursion_data.location.Point()));

      DCHECK(GetLayoutBox());
      if (GetLayoutBox()->HitTestOverflowControl(result, HitTestLocation(point),
                                                 PhysicalOffset()))
        return this;
    }
  }

  // We can only reach an SVG foreign object's PaintLayer from
  // LayoutSVGForeignObject::NodeAtFloatPoint (because
  // IsReplacedNormalFlowStacking() true for LayoutSVGForeignObject),
  // where the hit_test_rect has already been transformed to local coordinates.
  bool use_transform = false;
  if (!layout_object.IsSVGForeignObject() &&
      // Only a layer that can contain all descendants can become a transform
      // container. This excludes layout objects having transform nodes created
      // for animating opacity etc. or for backface-visibility:hidden.
      layout_object.CanContainFixedPositionObjects()) {
    DCHECK(layout_object.CanContainAbsolutePositionObjects());
    if (const auto* properties =
            layout_object.FirstFragment().PaintProperties()) {
      if (properties->HasCSSTransformPropertyNode() ||
          properties->Perspective())
        use_transform = true;
    }
  }

  // Apply a transform if we have one.
  if (use_transform && !applied_transform) {
    return HitTestTransformedLayerInFragments(
        transform_container, container_fragment, result, recursion_data,
        container_transform_state, z_offset, overflow_controls_only,
        clip_behavior);
  }

  // Don't hit test the clip-path area when checking for occlusion. This is
  // necessary because SVG doesn't support rect-based hit testing, so
  // HitTestClippedOutByClipPath may erroneously return true for a rect-based
  // hit test).
  bool is_occlusion_test = result.GetHitTestRequest().GetType() &
                           HitTestRequest::kHitTestVisualOverflow;
  if (!is_occlusion_test && layout_object.HasClipPath() &&
      HitTestClippedOutByClipPath(transform_container,
                                  recursion_data.location)) {
    return nullptr;
  }

  HitTestingTransformState* local_transform_state = nullptr;
  STACK_UNINITIALIZED std::optional<HitTestingTransformState> storage;

  if (applied_transform) {
    // We computed the correct state in the caller (above code), so just
    // reference it.
    DCHECK(container_transform_state);
    local_transform_state = container_transform_state;
  } else if (container_transform_state || has3d_transformed_descendant_) {
    DCHECK(!Preserves3D());
    // We need transform state for the first time, or to offset the container
    // state, so create it here.
    FragmentDataIterator iterator(layout_object);
    const FragmentData* local_fragment_for_transform_state =
        iterator.GetFragmentData();
    const FragmentData* container_fragment_for_transform_state;
    if (container_fragment_data) {
      container_fragment_for_transform_state = container_fragment_data;
      const auto& container_transform =
          container_fragment_data->ContentsProperties().Transform();
      while (!iterator.IsDone()) {
        // Find the first local fragment that is a descendant of
        // container_fragment.
        if (container_transform.IsAncestorOf(
                local_fragment_for_transform_state->LocalBorderBoxProperties()
                    .Transform())) {
          break;
        }
        ++iterator;
        local_fragment_for_transform_state = iterator.GetFragmentData();
      }
      if (!local_fragment_for_transform_state)
        return nullptr;
    } else {
      container_fragment_for_transform_state =
          &container_layout_object.FirstFragment();
    }
    storage = CreateLocalTransformState(
        transform_container, *container_fragment_for_transform_state,
        *local_fragment_for_transform_state, recursion_data,
        container_transform_state);
    local_transform_state = &*storage;
  }

  // Check for hit test on backface if backface-visibility is 'hidden'
  if (local_transform_state &&
      layout_object.StyleRef().BackfaceVisibility() ==
          EBackfaceVisibility::kHidden &&
      local_transform_state->AccumulatedTransform().IsBackFaceVisible()) {
    return nullptr;
  }

  // The following are used for keeping track of the z-depth of the hit point of
  // 3d-transformed descendants.
  double local_z_offset = -std::numeric_limits<double>::infinity();
  double* z_offset_for_descendants_ptr = nullptr;
  double* z_offset_for_contents_ptr = nullptr;

  bool depth_sort_descendants = false;
  if (Preserves3D()) {
    depth_sort_descendants = true;
    // Our layers can depth-test with our container, so share the z depth
    // pointer with the container, if it passed one down.
    z_offset_for_descendants_ptr = z_offset ? z_offset : &local_z_offset;
    z_offset_for_contents_ptr = z_offset ? z_offset : &local_z_offset;
  } else if (z_offset) {
    z_offset_for_descendants_ptr = nullptr;
    // Container needs us to give back a z offset for the hit layer.
    z_offset_for_contents_ptr = z_offset;
  }

  // Collect the fragments. This will compute the clip rectangles for each
  // layer fragment.
  PaintLayerFragments layer_fragments;
  ClearCollectionScope<PaintLayerFragments> scope(&layer_fragments);
  if (recursion_data.intersects_location) {
    if (applied_transform) {
      DCHECK_EQ(&transform_container, this);
      AppendSingleFragmentForHitTesting(layer_fragments, container_fragment,
                                        clip_behavior);
    } else {
      CollectFragments(layer_fragments, &transform_container, clip_behavior,
                       container_fragment_data);
    }

    // See if the hit test pos is inside the overflow controls of current layer.
    // This should be done before walking child layers to avoid that the
    // overflow controls are obscured by the positive child layers.
    if (scrollable_area_ &&
        layer_fragments[0].background_rect.Intersects(
            recursion_data.location) &&
        GetLayoutBox()->HitTestOverflowControl(
            result, recursion_data.location, layer_fragments[0].layer_offset)) {
      return this;
    }
  }

  if (overflow_controls_only)
    return nullptr;

  // This variable tracks which layer the mouse ends up being inside.
  PaintLayer* candidate_layer = nullptr;

  // Begin by walking our list of positive layers from highest z-index down to
  // the lowest z-index.
  PaintLayer* hit_layer = HitTestChildren(
      kPositiveZOrderChildren, transform_container, container_fragment, result,
      recursion_data, container_transform_state, z_offset_for_descendants_ptr,
      z_offset, local_transform_state, depth_sort_descendants);
  if (hit_layer) {
    if (!depth_sort_descendants)
      return hit_layer;
    candidate_layer = hit_layer;
  }

  // Now check our overflow objects.
  hit_layer = HitTestChildren(
      kNormalFlowChildren, transform_container, container_fragment, result,
      recursion_data, container_transform_state, z_offset_for_descendants_ptr,
      z_offset, local_transform_state, depth_sort_descendants);
  if (hit_layer) {
    if (!depth_sort_descendants)
      return hit_layer;
    candidate_layer = hit_layer;
  }

  const LayoutObject* stop_node = result.GetHitTestRequest().GetStopNode();
  if (recursion_data.intersects_location) {
    // Next we want to see if the mouse pos is inside the child LayoutObjects of
    // the layer. Check every fragment in reverse order.
    if (IsSelfPaintingLayer() &&
        !layout_object.ChildPaintBlockedByDisplayLock()) {
      // Hit test with a temporary HitTestResult, because we only want to commit
      // to 'result' if we know we're frontmost.
      STACK_UNINITIALIZED HitTestResult temp_result(
          result.GetHitTestRequest(), recursion_data.original_location);
      bool inside_fragment_foreground_rect = false;

      if (HitTestForegroundForFragments(layer_fragments, temp_result,
                                        recursion_data.location,
                                        inside_fragment_foreground_rect) &&
          IsHitCandidateForDepthOrder(this, false, z_offset_for_contents_ptr,
                                      local_transform_state) &&
          IsHitCandidateForStopNode(GetLayoutObject(), stop_node)) {
        if (result.GetHitTestRequest().ListBased())
          result.Append(temp_result);
        else
          result = temp_result;
        if (!depth_sort_descendants)
          return this;
        // Foreground can depth-sort with descendant layers, so keep this as a
        // candidate.
        candidate_layer = this;
      } else if (inside_fragment_foreground_rect &&
                 result.GetHitTestRequest().ListBased() &&
                 IsHitCandidateForStopNode(GetLayoutObject(), stop_node)) {
        result.Append(temp_result);
      }
    }
  }

  // Now check our negative z-index children.
  hit_layer = HitTestChildren(
      kNegativeZOrderChildren, transform_container, container_fragment, result,
      recursion_data, container_transform_state, z_offset_for_descendants_ptr,
      z_offset, local_transform_state, depth_sort_descendants);
  if (hit_layer) {
    if (!depth_sort_descendants)
      return hit_layer;
    candidate_layer = hit_layer;
  }

  // If we found a layer, return. Child layers, and foreground always render
  // in front of background.
  if (candidate_layer)
    return candidate_layer;

  if (recursion_data.intersects_location && IsSelfPaintingLayer()) {
    STACK_UNINITIALIZED HitTestResult temp_result(
        result.GetHitTestRequest(), recursion_data.original_location);
    bool inside_fragment_background_rect = false;
    if (HitTestFragmentsWithPhase(layer_fragments, temp_result,
                                  recursion_data.location,
                                  HitTestPhase::kSelfBlockBackground,
                                  inside_fragment_background_rect) &&
        IsHitCandidateForDepthOrder(this, false, z_offset_for_contents_ptr,
                                    local_transform_state) &&
        IsHitCandidateForStopNode(GetLayoutObject(), stop_node)) {
      if (result.GetHitTestRequest().ListBased())
        result.Append(temp_result);
      else
        result = temp_result;
      return this;
    }
    if (inside_fragment_background_rect &&
        result.GetHitTestRequest().ListBased() &&
        IsHitCandidateForStopNode(GetLayoutObject(), stop_node)) {
      result.Append(temp_result);
    }
  }

  return nullptr;
}

bool PaintLayer::HitTestForegroundForFragments(
    const PaintLayerFragments& layer_fragments,
    HitTestResult& result,
    const HitTestLocation& hit_test_location,
    bool& inside_clip_rect) const {
  if (HitTestFragmentsWithPhase(layer_fragments, result, hit_test_location,
                                HitTestPhase::kForeground, inside_clip_rect)) {
    return true;
  }
  if (inside_clip_rect &&
      HitTestFragmentsWithPhase(layer_fragments, result, hit_test_location,
                                HitTestPhase::kFloat, inside_clip_rect)) {
    return true;
  }
  if (inside_clip_rect &&
      HitTestFragmentsWithPhase(layer_fragments, result, hit_test_location,
                                HitTestPhase::kDescendantBlockBackgrounds,
                                inside_clip_rect)) {
    return true;
  }
  return false;
}

bool PaintLayer::HitTestFragmentsWithPhase(
    const PaintLayerFragments& layer_fragments,
    HitTestResult& result,
    const HitTestLocation& hit_test_location,
    HitTestPhase phase,
    bool& inside_clip_rect) const {
  if (layer_fragments.empty())
    return false;

  for (int i = layer_fragments.size() - 1; i >= 0; --i) {
    const PaintLayerFragment& fragment = layer_fragments.at(i);
    const ClipRect& bounds = phase == HitTestPhase::kSelfBlockBackground
                                 ? fragment.background_rect
                                 : fragment.foreground_rect;
    if (!bounds.Intersects(hit_test_location))
      continue;

    inside_clip_rect = true;

    if (GetLayoutObject().IsLayoutInline() &&
        GetLayoutObject().CanTraversePhysicalFragments()) [[unlikely]] {
      // When hit-testing an inline that has a layer, we'll search for it in
      // each fragment of the containing block. Each fragment has its own
      // offset, and we need to do one fragment at a time. If the inline uses a
      // transform, though, we'll only have one PaintLayerFragment in the list
      // at this point (we iterate over them further up on the stack, and pass a
      // "list" of one fragment at a time from there instead).
      DCHECK(fragment.fragment_idx != WTF::kNotFound);
      HitTestLocation location_for_fragment(hit_test_location,
                                            fragment.fragment_idx);
      if (HitTestFragmentWithPhase(result, fragment.physical_fragment,
                                   fragment.layer_offset, location_for_fragment,
                                   phase))
        return true;
    } else if (HitTestFragmentWithPhase(result, fragment.physical_fragment,
                                        fragment.layer_offset,
                                        hit_test_location, phase)) {
      return true;
    }
  }

  return false;
}

PaintLayer* PaintLayer::HitTestTransformedLayerInFragments(
    const PaintLayer& transform_container,
    const PaintLayerFragment* container_fragment,
    HitTestResult& result,
    const HitTestRecursionData& recursion_data,
    HitTestingTransformState* container_transform_state,
    double* z_offset,
    bool overflow_controls_only,
    ShouldRespectOverflowClipType clip_behavior) {
  const FragmentData* container_fragment_data =
      container_fragment ? container_fragment->fragment_data : nullptr;
  PaintLayerFragments fragments;
  ClearCollectionScope<PaintLayerFragments> scope(&fragments);

  CollectFragments(fragments, &transform_container, clip_behavior,
                   container_fragment_data);

  for (const auto& fragment : fragments) {
    // Apply any clips established by layers in between us and the root layer.
    if (!fragment.background_rect.Intersects(recursion_data.location))
      continue;

    PaintLayer* hit_layer = HitTestLayerByApplyingTransform(
        transform_container, container_fragment, fragment, result,
        recursion_data, container_transform_state, z_offset,
        overflow_controls_only);
    if (hit_layer)
      return hit_layer;
  }

  return nullptr;
}

PaintLayer* PaintLayer::HitTestLayerByApplyingTransform(
    const PaintLayer& transform_container,
    const PaintLayerFragment* container_fragment,
    const PaintLayerFragment& local_fragment,
    HitTestResult& result,
    const HitTestRecursionData& recursion_data,
    HitTestingTransformState* root_transform_state,
    double* z_offset,
    bool overflow_controls_only,
    const PhysicalOffset& translation_offset) {
  // Create a transform state to accumulate this transform.
  HitTestingTransformState new_transform_state = CreateLocalTransformState(
      transform_container,
      container_fragment
          ? *container_fragment->fragment_data
          : transform_container.GetLayoutObject().FirstFragment(),
      *local_fragment.fragment_data, recursion_data, root_transform_state);

  // If the transform can't be inverted, then don't hit test this layer at all.
  if (!new_transform_state.AccumulatedTransform().IsInvertible())
    return nullptr;

  // Compute the point and the hit test rect in the coords of this layer by
  // using the values from new_transform_state, which store the point and quad
  // in the coords of the last flattened layer, and the accumulated transform
  // which lets up map through preserve-3d layers.
  //
  // We can't just map HitTestLocation and HitTestRect because they may have
  // been flattened (losing z) by our container.
  gfx::PointF local_point = new_transform_state.MappedPoint();
  PhysicalRect bounds_of_mapped_area = new_transform_state.BoundsOfMappedArea();
  std::optional<HitTestLocation> new_location;
  if (recursion_data.location.IsRectBasedTest())
    new_location.emplace(local_point, new_transform_state.MappedQuad());
  else
    new_location.emplace(local_point, new_transform_state.BoundsOfMappedQuad());
  HitTestRecursionData new_recursion_data(bounds_of_mapped_area, *new_location,
                                          recursion_data.original_location);

  // Now do a hit test with the transform container shifted to this layer.
  // As an optimization, pass nullptr as the new container_fragment if this
  // layer has only one fragment.
  const auto* new_container_fragment =
      GetLayoutObject().IsFragmented() ? &local_fragment : nullptr;
  return HitTestLayer(*this, new_container_fragment, result, new_recursion_data,
                      /*applied_transform*/ true, &new_transform_state,
                      z_offset, overflow_controls_only);
}

bool PaintLayer::HitTestFragmentWithPhase(
    HitTestResult& result,
    const PhysicalBoxFragment* physical_fragment,
    const PhysicalOffset& fragment_offset,
    const HitTestLocation& hit_test_location,
    HitTestPhase phase) const {
  DCHECK(IsSelfPaintingLayer() || HasSelfPaintingLayerDescendant());

  bool did_hit;
  if (physical_fr
"""


```