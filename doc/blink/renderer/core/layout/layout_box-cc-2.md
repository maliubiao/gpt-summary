Response:
The user wants a summary of the functionality of the provided C++ code snippet from the Chromium Blink engine, specifically the `LayoutBox` class. I need to identify the key responsibilities of this class based on the methods present in the code. I should also look for connections to web technologies like JavaScript, HTML, and CSS. The prompt also asks for examples of logical reasoning with input and output, and common usage errors. Finally, I need to remember this is part 3 of 6.

Here's a plan:

1. **Identify Core Functionality:** Go through the methods and group them by their apparent purpose. Look for keywords like "clip," "transform," "hitTest," "paint," "layout," etc.
2. **Relate to Web Technologies:** For each functional area, consider how it relates to HTML elements, CSS properties, and potential JavaScript interactions.
3. **Logical Reasoning Examples:** Choose a function and devise hypothetical input states and their expected output based on the code.
4. **Common Usage Errors:** Think about how developers might misuse or misunderstand the functionality represented by the code.
5. **Part 3 Context:** Briefly acknowledge that this is a section within a larger file.
6. **Structure the Output:**  Organize the information clearly with headings and bullet points.
这是一个 `LayoutBox.cc` 文件代码片段，属于 Chromium Blink 渲染引擎，它定义了 `LayoutBox` 类的部分功能。根据提供的代码片段，我们可以归纳出以下功能：

**核心功能归纳:**

* **裁剪 (Clipping):**
    * 计算元素的裁剪区域 (`ClippingRect`, `OverflowClipRect`, `ClipRect`)，考虑了 overflow 属性、clip 属性、滚动条等因素。
    * 应用裁剪 (`ApplyBoxClips`)，将裁剪区域应用到变换状态中。
* **坐标映射和变换 (Coordinate Mapping and Transformation):**
    * 将元素的视觉矩形映射到容器空间 (`MapVisualRectToContainer`)，涉及矩阵变换、容器偏移、滚动偏移、透视等。
    * 将元素内容矩形映射到盒子空间 (`MapContentsRectToBoxSpace`)，主要处理裁剪和滚动。
    * 计算透视原点 (`PerspectiveOrigin`).
* **命中测试 (Hit Testing):**
    * 判断点是否在元素的范围内 (`MayIntersect`).
    * 执行溢出控制的命中测试 (`HitTestOverflowControl`)，例如滚动条。
    * 在元素的指定阶段执行命中测试 (`NodeAtPoint`)，考虑了裁剪、子元素等因素。
    * 命中测试子元素 (`HitTestChildren`).
    * 判断点是否被圆角边框裁剪 (`HitTestClippedOutByBorder`).
* **绘制 (Painting):**
    * 提供背景绘制范围 (`BackgroundPaintedExtent`).
    * 判断背景是否已知是不透明的 (`BackgroundIsKnownToBeOpaqueInRect`)，用于优化绘制。
    * 判断前景是否已知是不透明的 (`ForegroundIsKnownToBeOpaqueInRect`)，同样用于优化绘制。
    * 计算背景是否已知被遮挡 (`ComputeBackgroundIsKnownToBeObscured`).
    * 处理图片变更事件 (`ImageChanged`)，触发重绘或属性更新。
    * 计算资源优先级 (`ComputeResourcePriority`)，可能用于优化资源加载。
    * 标记需要重绘 (`InvalidatePaint`).
    * 清除绘制相关的标记 (`ClearPaintFlags`).
* **布局相关 (Layout Related):**
    * 提供覆盖包含块内容逻辑宽度的功能 (`OverrideContainingBlockContentLogicalWidth` 等)。
    * 获取包含块的逻辑高度 (`ContainingBlockLogicalHeightForRelPositioned`).
    * 获取包含块的内容逻辑宽度 (`ContainingBlockLogicalWidthForContent`).
    * 计算相对于容器的偏移 (`OffsetFromContainerInternal`)，考虑了粘性定位和滚动。
    * 管理内联片段 (`HasInlineFragments`, `SetFirstInlineFragmentItemIndex` 等)。
    * 管理布局结果缓存 (`AddMeasureLayoutResult`, `SetCachedLayoutResult`).
* **生命周期和状态管理:**
    * 处理位置变化 (`LocationChanged`).
    * 处理尺寸变化 (`SizeChanged`).
    * 判断是否与可见视口相交 (`IntersectsVisibleViewport`).
    * 确保对象已准备好进行重绘失效 (`EnsureIsReadyForPaintInvalidation`).

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **CSS 的 `overflow` 属性:** `ShouldClipOverflowAlongEitherAxis()`, `OverflowClipRect()` 等方法直接与 CSS 的 `overflow: hidden`, `overflow: scroll`, `overflow: auto` 等属性相关。
    * **例子:** 当一个 HTML 元素的 CSS 样式设置为 `overflow: hidden;` 时，`ShouldClipOverflowAlongEitherAxis()` 会返回 `true`，`OverflowClipRect()` 会计算出该元素内容区域的裁剪矩形，超出这个矩形的内容将不会被显示。
* **CSS 的 `clip` 属性:** `ClipRect()` 方法处理 CSS 的 `clip` 属性，用于定义元素的哪个部分应该可见。
    * **例子:** HTML 元素的 CSS 样式设置为 `clip: rect(10px, 50px, 100px, 20px);` 时，`ClipRect()` 会计算出一个矩形，只有这个矩形内的内容会被渲染。
* **CSS 的 `transform` 属性:** `MapVisualRectToContainer()` 方法在计算坐标映射时会考虑 CSS 的 `transform` 属性，包括 `translate`, `rotate`, `scale`, `skew` 等。
    * **例子:** 当一个 HTML 元素应用了 `transform: rotate(45deg);` 时，`MapVisualRectToContainer()` 会计算出旋转后的元素在父元素坐标系中的位置。
* **CSS 的 `perspective` 和 `perspective-origin` 属性:** `PerspectiveOrigin()` 方法计算透视原点，`MapVisualRectToContainer()` 中会应用容器的透视效果。
    * **例子:** 父元素设置了 `perspective: 800px;` 和 `perspective-origin: 50% 50%;`，子元素在 `MapVisualRectToContainer()` 中计算位置时，会根据父元素的透视属性进行变换。
* **CSS 的 `border-radius` 属性:** `HitTestClippedOutByBorder()` 和 `NodeAtPoint()` 中会考虑 `border-radius` 造成的裁剪效果。
    * **例子:** 当一个 HTML 元素设置了 `border-radius: 10px;`，点击元素边角未被圆角覆盖的区域时，`HitTestClippedOutByBorder()` 会返回 `true`，表明点击位置不在元素的可交互区域内。
* **CSS 的 `visibility` 属性:** `ForegroundIsKnownToBeOpaqueInRect()` 会检查元素的 `visibility` 属性。
    * **例子:** 如果一个 HTML 元素的 CSS 样式设置为 `visibility: hidden;`，则 `ForegroundIsKnownToBeOpaqueInRect()` 在判断其是否遮挡下方元素时会将其排除。
* **CSS 的背景相关属性 (例如 `background-image`):** `ImageChanged()` 方法会监听背景图片的加载完成或错误，并触发重绘。
    * **例子:** 当 HTML 元素的 CSS 样式中使用了 `background-image: url('image.png');`，并且图片加载完成后，`ImageChanged()` 会被调用，导致该元素进行重绘。
* **CSS 的 `position: sticky;` 属性:** `OffsetFromContainerInternal()` 方法会处理粘性定位元素的偏移。
    * **例子:** 当一个 HTML 元素的 CSS 样式设置为 `position: sticky; top: 10px;`，在滚动过程中，`OffsetFromContainerInternal()` 会根据滚动位置计算出元素相对于其滚动容器的偏移。
* **HTML 元素类型:** 代码中针对特定的 HTML 元素类型（例如 `HTMLInputElement`, `MenuList`）有特殊的处理逻辑，例如 `HasControlClip()`。
    * **例子:** 对于 `<input>` 元素，`HasControlClip()` 会返回 `true`，表明需要应用额外的控制裁剪。

**逻辑推理的假设输入与输出举例:**

**假设输入:**

* 一个 `LayoutBox` 对象代表一个 `div` 元素，其 CSS 样式为:
    ```css
    .box {
      width: 100px;
      height: 100px;
      overflow: hidden;
    }
    ```
* 调用 `OverflowClipRect()` 方法，`location` 参数为 `PhysicalOffset(0, 0)`。

**逻辑推理:**

* `ShouldClipOverflowAlongEitherAxis()` 会因为 `overflow: hidden` 返回 `true`。
* `OverflowClipRect()` 会创建一个 `PhysicalRect` 对象。
* 由于没有滚动条，且 `overflow` 为 `hidden`，裁剪区域将与元素的内容区域大小一致。

**预期输出:**

* `OverflowClipRect()` 返回的 `PhysicalRect` 对象的 `size` 为 `(100, 100)`，`offset` 为 `(0, 0)`。

**用户或编程常见的使用错误举例:**

* **误解裁剪行为:** 开发者可能认为通过 JavaScript 修改元素的 `offsetWidth` 或 `offsetHeight` 就能改变元素的裁剪区域。实际上，裁剪是由 CSS 属性控制的，需要修改 CSS 属性才能生效。
* **忘记考虑变换对坐标的影响:** 在进行命中测试或计算元素位置时，如果没有考虑 CSS 的 `transform` 属性，可能会得到错误的坐标，导致交互或动画效果不正确。例如，点击一个旋转后的元素，如果没有进行正确的坐标转换，可能会点击到错误的位置。
* **过度依赖 JavaScript 操作布局信息:**  频繁地使用 JavaScript 获取布局信息（例如 `getBoundingClientRect`）可能导致性能问题，因为这会触发浏览器的回流（reflow）。开发者应该尽量使用 CSS 来实现布局和样式效果。
* **不理解 `z-index` 和层叠上下文:** 在处理元素的遮挡关系时，如果没有理解 CSS 的 `z-index` 和层叠上下文的概念，可能会导致元素的层叠顺序不符合预期。

**这是第3部分，共6部分，请归纳一下它的功能:**

结合上下文，这部分代码主要关注 `LayoutBox` 的 **裁剪、坐标映射和变换、命中测试以及部分绘制相关的逻辑**。它定义了 `LayoutBox` 如何确定其可见区域，如何在不同的坐标系之间转换，以及如何响应用户的点击事件。这部分功能是渲染引擎中至关重要的一部分，直接影响到网页的布局、渲染和交互。

### 提示词
```
这是目录为blink/renderer/core/layout/layout_box.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
set& location) const {
  NOT_DESTROYED();
  PhysicalRect result(InfiniteIntRect());
  if (ShouldClipOverflowAlongEitherAxis())
    result = OverflowClipRect(location);

  if (HasClip())
    result.Intersect(ClipRect(location));

  return result;
}

gfx::PointF LayoutBox::PerspectiveOrigin(const PhysicalSize* size) const {
  if (!HasTransformRelatedProperty())
    return gfx::PointF();

  // Use the |size| parameter instead of |Size()| if present.
  gfx::SizeF float_size = size ? gfx::SizeF(*size) : gfx::SizeF(Size());

  return PointForLengthPoint(StyleRef().PerspectiveOrigin(), float_size);
}

bool LayoutBox::MapVisualRectToContainer(
    const LayoutObject* container_object,
    const PhysicalOffset& container_offset,
    const LayoutObject* ancestor,
    VisualRectFlags visual_rect_flags,
    TransformState& transform_state) const {
  NOT_DESTROYED();
  bool container_preserve_3d = container_object->StyleRef().Preserves3D() &&
                               container_object == NearestAncestorForElement();

  TransformState::TransformAccumulation accumulation =
      container_preserve_3d ? TransformState::kAccumulateTransform
                            : TransformState::kFlattenTransform;

  // If there is no transform on this box, adjust for container offset and
  // container scrolling, then apply container clip.
  if (!ShouldUseTransformFromContainer(container_object)) {
    transform_state.Move(container_offset, accumulation);
    if (container_object->IsBox() && container_object != ancestor &&
        !To<LayoutBox>(container_object)
             ->MapContentsRectToBoxSpace(transform_state, accumulation, *this,
                                         visual_rect_flags)) {
      return false;
    }
    return true;
  }

  // Otherwise, do the following:
  // 1. Expand for pixel snapping.
  // 2. Generate transformation matrix combining, in this order
  //    a) transform,
  //    b) container offset,
  //    c) container scroll offset,
  //    d) perspective applied by container.
  // 3. Apply transform Transform+flattening.
  // 4. Apply container clip.

  // 1. Expand for pixel snapping.
  // Use EnclosingBoundingBox because we cannot properly compute pixel
  // snapping for painted elements within the transform since we don't know
  // the desired subpixel accumulation at this point, and the transform may
  // include a scale. This only makes sense for non-preserve3D.
  //
  // TODO(dbaron): Does the flattening here need to be done for the
  // early return case above as well?
  // (Why is this flattening needed in addition to the flattening done by
  // using TransformState::kAccumulateTransform?)
  if (!StyleRef().Preserves3D()) {
    transform_state.Flatten();
    transform_state.SetQuad(gfx::QuadF(gfx::RectF(
        gfx::ToEnclosingRect(transform_state.LastPlanarQuad().BoundingBox()))));
  }

  // 2. Generate transformation matrix.
  // a) Transform.
  gfx::Transform transform;
  if (Layer() && Layer()->Transform())
    transform.PreConcat(Layer()->CurrentTransform());

  // b) Container offset.
  transform.PostTranslate(container_offset.left.ToFloat(),
                          container_offset.top.ToFloat());

  // c) Container scroll offset.
  if (container_object->IsBox() && container_object != ancestor &&
      To<LayoutBox>(container_object)->ContainedContentsScroll(*this)) {
    PhysicalOffset offset(
        -To<LayoutBox>(container_object)->ScrolledContentOffset());
    transform.PostTranslate(offset.left, offset.top);
  }

  bool has_perspective = container_object && container_object->HasLayer() &&
                         container_object->StyleRef().HasPerspective();
  if (has_perspective && container_object != NearestAncestorForElement()) {
    has_perspective = false;

    if (StyleRef().Preserves3D() || transform.Creates3d()) {
      UseCounter::Count(GetDocument(),
                        WebFeature::kDifferentPerspectiveCBOrParent);
    }
  }

  // d) Perspective applied by container.
  if (has_perspective) {
    // Perspective on the container affects us, so we have to factor it in here.
    DCHECK(container_object->HasLayer());
    gfx::PointF perspective_origin;
    if (const auto* container_box = DynamicTo<LayoutBox>(container_object))
      perspective_origin = container_box->PerspectiveOrigin();

    gfx::Transform perspective_matrix;
    perspective_matrix.ApplyPerspectiveDepth(
        container_object->StyleRef().UsedPerspective());
    perspective_matrix.ApplyTransformOrigin(perspective_origin.x(),
                                            perspective_origin.y(), 0);

    transform = perspective_matrix * transform;
  }

  // 3. Apply transform and flatten.
  transform_state.ApplyTransform(transform, accumulation);
  if (!container_preserve_3d)
    transform_state.Flatten();

  // 4. Apply container clip.
  if (container_object->IsBox() && container_object != ancestor &&
      container_object->HasClipRelatedProperty()) {
    return To<LayoutBox>(container_object)
        ->ApplyBoxClips(transform_state, accumulation, visual_rect_flags);
  }

  return true;
}

bool LayoutBox::MapContentsRectToBoxSpace(
    TransformState& transform_state,
    TransformState::TransformAccumulation accumulation,
    const LayoutObject& contents,
    VisualRectFlags visual_rect_flags) const {
  NOT_DESTROYED();
  if (!HasClipRelatedProperty())
    return true;

  if (ContainedContentsScroll(contents))
    transform_state.Move(-ScrolledContentOffset());

  return ApplyBoxClips(transform_state, accumulation, visual_rect_flags);
}

bool LayoutBox::ContainedContentsScroll(const LayoutObject& contents) const {
  NOT_DESTROYED();
  if (IsA<LayoutView>(this) &&
      contents.StyleRef().GetPosition() == EPosition::kFixed) {
    return false;
  }
  return IsScrollContainer();
}

bool LayoutBox::ApplyBoxClips(
    TransformState& transform_state,
    TransformState::TransformAccumulation accumulation,
    VisualRectFlags visual_rect_flags) const {
  NOT_DESTROYED();
  // This won't work fully correctly for fixed-position elements, who should
  // receive CSS clip but for whom the current object is not in the containing
  // block chain.
  PhysicalRect clip_rect = ClippingRect(PhysicalOffset());

  transform_state.Flatten();
  PhysicalRect rect(
      gfx::ToEnclosingRect(transform_state.LastPlanarQuad().BoundingBox()));
  bool does_intersect;
  if (visual_rect_flags & kEdgeInclusive) {
    does_intersect = rect.InclusiveIntersect(clip_rect);
  } else {
    rect.Intersect(clip_rect);
    does_intersect = !rect.IsEmpty();
  }
  transform_state.SetQuad(gfx::QuadF(gfx::RectF(rect)));

  return does_intersect;
}

// TODO (lajava) Shouldn't we implement these functions based on physical
// direction ?.
LayoutUnit LayoutBox::OverrideContainingBlockContentLogicalWidth() const {
  NOT_DESTROYED();
  DCHECK(HasOverrideContainingBlockContentLogicalWidth());
  return rare_data_->override_containing_block_content_logical_width_;
}

// TODO (lajava) Shouldn't we implement these functions based on physical
// direction ?.
bool LayoutBox::HasOverrideContainingBlockContentLogicalWidth() const {
  NOT_DESTROYED();
  return rare_data_ &&
         rare_data_->has_override_containing_block_content_logical_width_;
}

// TODO (lajava) Shouldn't we implement these functions based on physical
// direction ?.
void LayoutBox::SetOverrideContainingBlockContentLogicalWidth(
    LayoutUnit logical_width) {
  NOT_DESTROYED();
  DCHECK_GE(logical_width, LayoutUnit(-1));
  EnsureRareData().override_containing_block_content_logical_width_ =
      logical_width;
  EnsureRareData().has_override_containing_block_content_logical_width_ = true;
}

// TODO (lajava) Shouldn't we implement these functions based on physical
// direction ?.
void LayoutBox::ClearOverrideContainingBlockContentSize() {
  NOT_DESTROYED();
  if (!rare_data_)
    return;
  EnsureRareData().has_override_containing_block_content_logical_width_ = false;
}

bool LayoutBox::HitTestAllPhases(HitTestResult& result,
                                 const HitTestLocation& hit_test_location,
                                 const PhysicalOffset& accumulated_offset) {
  NOT_DESTROYED();
  if (!MayIntersect(result, hit_test_location, accumulated_offset))
    return false;
  return LayoutObject::HitTestAllPhases(result, hit_test_location,
                                        accumulated_offset);
}

bool LayoutBox::HitTestOverflowControl(
    HitTestResult& result,
    const HitTestLocation& hit_test_location,
    const PhysicalOffset& adjusted_location) const {
  NOT_DESTROYED();

  auto* scrollable_area = GetScrollableArea();
  if (!scrollable_area)
    return false;

  if (!VisibleToHitTestRequest(result.GetHitTestRequest()))
    return false;

  PhysicalOffset local_point = hit_test_location.Point() - adjusted_location;
  if (!scrollable_area->HitTestOverflowControls(result,
                                                ToRoundedPoint(local_point)))
    return false;

  UpdateHitTestResult(result, local_point);
  return result.AddNodeToListBasedTestResult(
             NodeForHitTest(), hit_test_location) == kStopHitTesting;
}

bool LayoutBox::NodeAtPoint(HitTestResult& result,
                            const HitTestLocation& hit_test_location,
                            const PhysicalOffset& accumulated_offset,
                            HitTestPhase phase) {
  NOT_DESTROYED();
  if (!MayIntersect(result, hit_test_location, accumulated_offset))
    return false;

  if (phase == HitTestPhase::kForeground && !HasSelfPaintingLayer() &&
      HitTestOverflowControl(result, hit_test_location, accumulated_offset))
    return true;

  bool skip_children = (result.GetHitTestRequest().GetStopNode() == this) ||
                       ChildPaintBlockedByDisplayLock();
  if (!skip_children && ShouldClipOverflowAlongEitherAxis()) {
    // PaintLayer::HitTestFragmentsWithPhase() checked the fragments'
    // foreground rect for intersection if a layer is self painting,
    // so only do the overflow clip check here for non-self-painting layers.
    if (!HasSelfPaintingLayer() &&
        !hit_test_location.Intersects(OverflowClipRect(
            accumulated_offset, kExcludeOverlayScrollbarSizeForHitTesting))) {
      skip_children = true;
    }
    if (!skip_children && StyleRef().HasBorderRadius()) {
      PhysicalRect bounds_rect(accumulated_offset, Size());
      skip_children = !hit_test_location.Intersects(
          RoundedBorderGeometry::PixelSnappedRoundedInnerBorder(StyleRef(),
                                                                bounds_rect));
    }
  }

  if (!skip_children &&
      HitTestChildren(result, hit_test_location, accumulated_offset, phase)) {
    return true;
  }

  if (StyleRef().HasBorderRadius() &&
      HitTestClippedOutByBorder(hit_test_location, accumulated_offset))
    return false;

  // Now hit test ourselves.
  if (IsInSelfHitTestingPhase(phase) &&
      VisibleToHitTestRequest(result.GetHitTestRequest())) {
    PhysicalRect bounds_rect;
    if (result.GetHitTestRequest().IsHitTestVisualOverflow()) [[unlikely]] {
      bounds_rect = VisualOverflowRectIncludingFilters();
    } else {
      bounds_rect = PhysicalBorderBoxRect();
    }
    bounds_rect.Move(accumulated_offset);
    if (hit_test_location.Intersects(bounds_rect)) {
      UpdateHitTestResult(result,
                          hit_test_location.Point() - accumulated_offset);
      if (result.AddNodeToListBasedTestResult(NodeForHitTest(),
                                              hit_test_location,
                                              bounds_rect) == kStopHitTesting)
        return true;
    }
  }

  return false;
}

bool LayoutBox::HitTestChildren(HitTestResult& result,
                                const HitTestLocation& hit_test_location,
                                const PhysicalOffset& accumulated_offset,
                                HitTestPhase phase) {
  NOT_DESTROYED();
  for (LayoutObject* child = SlowLastChild(); child;
       child = child->PreviousSibling()) {
    if (child->HasLayer() &&
        To<LayoutBoxModelObject>(child)->Layer()->IsSelfPaintingLayer())
      continue;

    PhysicalOffset child_accumulated_offset = accumulated_offset;
    if (auto* box = DynamicTo<LayoutBox>(child))
      child_accumulated_offset += box->PhysicalLocation(this);

    if (child->NodeAtPoint(result, hit_test_location, child_accumulated_offset,
                           phase))
      return true;
  }

  return false;
}

bool LayoutBox::HitTestClippedOutByBorder(
    const HitTestLocation& hit_test_location,
    const PhysicalOffset& border_box_location) const {
  NOT_DESTROYED();
  PhysicalRect border_rect = PhysicalBorderBoxRect();
  border_rect.Move(border_box_location);
  return !hit_test_location.Intersects(
      RoundedBorderGeometry::PixelSnappedRoundedBorder(StyleRef(),
                                                       border_rect));
}

void LayoutBox::Paint(const PaintInfo& paint_info) const {
  NOT_DESTROYED();
  NOTREACHED();
}

PhysicalRect LayoutBox::BackgroundPaintedExtent() const {
  NOT_DESTROYED();
  return PhysicalBackgroundRect(kBackgroundPaintedExtent);
}

bool LayoutBox::BackgroundIsKnownToBeOpaqueInRect(
    const PhysicalRect& local_rect) const {
  NOT_DESTROYED();
  // If the element has appearance, it might be painted by theme.
  // We cannot be sure if theme paints the background opaque.
  // In this case it is safe to not assume opaqueness.
  // FIXME: May be ask theme if it paints opaque.
  if (StyleRef().HasEffectiveAppearance())
    return false;
  // FIXME: Check the opaqueness of background images.

  // FIXME: Use rounded rect if border radius is present.
  if (StyleRef().HasBorderRadius())
    return false;
  if (HasClipPath())
    return false;
  if (StyleRef().HasBlendMode())
    return false;
  return PhysicalBackgroundRect(kBackgroundKnownOpaqueRect)
      .Contains(local_rect);
}

// Note that callers are responsible for checking
// ChildPaintBlockedByDisplayLock(), since that is a property of the parent
// rather than of the child.
static bool IsCandidateForOpaquenessTest(const LayoutBox& child_box) {
  // Skip all layers to simplify ForegroundIsKnownToBeOpaqueInRect(). This
  // covers cases of clipped, transformed, translucent, composited, etc.
  if (child_box.HasLayer())
    return false;
  const ComputedStyle& child_style = child_box.StyleRef();
  if (child_style.Visibility() != EVisibility::kVisible ||
      child_style.ShapeOutside()) {
    return false;
  }
  if (child_box.Size().IsZero())
    return false;
  // A replaced element with border-radius always clips the content.
  if (child_box.IsLayoutReplaced() && child_style.HasBorderRadius())
    return false;
  return true;
}

bool LayoutBox::ForegroundIsKnownToBeOpaqueInRect(
    const PhysicalRect& local_rect,
    unsigned max_depth_to_test) const {
  NOT_DESTROYED();
  if (!max_depth_to_test)
    return false;
  if (ChildPaintBlockedByDisplayLock())
    return false;
  for (LayoutObject* child = SlowFirstChild(); child;
       child = child->NextSibling()) {
    // We do not bother checking descendants of |LayoutInline|, including
    // block-in-inline, because the cost of checking them overweights the
    // benefits.
    if (!child->IsBox())
      continue;
    auto* child_box = To<LayoutBox>(child);
    if (!IsCandidateForOpaquenessTest(*child_box))
      continue;
    DCHECK(!child_box->IsPositioned());
    PhysicalRect child_local_rect = local_rect;
    child_local_rect.Move(-child_box->PhysicalLocation());
    if (child_local_rect.Y() < 0 || child_local_rect.X() < 0) {
      // If there is unobscured area above/left of a static positioned box then
      // the rect is probably not covered. This can cause false-negative in
      // non-horizontal-tb writing mode but is allowed.
      return false;
    }
    if (child_local_rect.Bottom() > child_box->Size().height ||
        child_local_rect.Right() > child_box->Size().width) {
      continue;
    }
    if (RuntimeEnabledFeatures::CompositeBGColorAnimationEnabled() &&
        child->Style()->HasCurrentBackgroundColorAnimation()) {
      return false;
    }
    if (child_box->BackgroundIsKnownToBeOpaqueInRect(child_local_rect))
      return true;
    if (child_box->ForegroundIsKnownToBeOpaqueInRect(child_local_rect,
                                                     max_depth_to_test - 1))
      return true;
  }
  return false;
}

DISABLE_CFI_PERF
bool LayoutBox::ComputeBackgroundIsKnownToBeObscured() const {
  NOT_DESTROYED();
  if (ScrollsOverflow())
    return false;
  // Test to see if the children trivially obscure the background.
  if (!StyleRef().HasBackground())
    return false;
  // Root background painting is special.
  if (IsA<LayoutView>(this))
    return false;
  if (StyleRef().BoxShadow())
    return false;
  return ForegroundIsKnownToBeOpaqueInRect(BackgroundPaintedExtent(),
                                           kBackgroundObscurationTestMaxDepth);
}

void LayoutBox::ImageChanged(WrappedImagePtr image,
                             CanDeferInvalidation defer) {
  NOT_DESTROYED();
  bool is_box_reflect_image =
      (StyleRef().BoxReflect() && StyleRef().BoxReflect()->Mask().GetImage() &&
       StyleRef().BoxReflect()->Mask().GetImage()->Data() == image);

  if (is_box_reflect_image && HasLayer()) {
    Layer()->SetFilterOnEffectNodeDirty();
    SetNeedsPaintPropertyUpdate();
  }

  // TODO(chrishtr): support delayed paint invalidation for animated border
  // images.
  if ((StyleRef().BorderImage().GetImage() &&
       StyleRef().BorderImage().GetImage()->Data() == image) ||
      (StyleRef().MaskBoxImage().GetImage() &&
       StyleRef().MaskBoxImage().GetImage()->Data() == image) ||
      is_box_reflect_image) {
    SetShouldDoFullPaintInvalidationWithoutLayoutChange(
        PaintInvalidationReason::kImage);
  } else {
    for (const FillLayer* layer = &StyleRef().MaskLayers(); layer;
         layer = layer->Next()) {
      if (layer->GetImage() && image == layer->GetImage()->Data()) {
        SetShouldDoFullPaintInvalidationWithoutLayoutChange(
            PaintInvalidationReason::kImage);
        if (layer->GetImage()->IsMaskSource() && IsSVGChild()) {
          // Since an invalid <mask> reference does not yield a paint property
          // on SVG content (see CSSMaskPainter), we need to update paint
          // properties when such a reference changes.
          SetNeedsPaintPropertyUpdate();
        }
        break;
      }
    }
  }

  if (!BackgroundTransfersToView()) {
    for (const FillLayer* layer = &StyleRef().BackgroundLayers(); layer;
         layer = layer->Next()) {
      if (layer->GetImage() && image == layer->GetImage()->Data()) {
        bool maybe_animated =
            layer->GetImage()->CachedImage() &&
            layer->GetImage()->CachedImage()->GetImage() &&
            layer->GetImage()->CachedImage()->GetImage()->MaybeAnimated();
        if (defer == CanDeferInvalidation::kYes && maybe_animated)
          SetMayNeedPaintInvalidationAnimatedBackgroundImage();
        else
          SetBackgroundNeedsFullPaintInvalidation();
        break;
      }
    }
  }

  ShapeValue* shape_outside_value = StyleRef().ShapeOutside();
  if (!GetFrameView()->IsInPerformLayout() && IsFloating() &&
      shape_outside_value && shape_outside_value->GetImage() &&
      shape_outside_value->GetImage()->Data() == image) {
    ShapeOutsideInfo& info = ShapeOutsideInfo::EnsureInfo(*this);
    if (!info.IsComputingShape()) {
      info.MarkShapeAsDirty();
      if (auto* containing_block = ContainingBlock()) {
        containing_block->SetChildNeedsLayout();
      }
    }
  }
}

ResourcePriority LayoutBox::ComputeResourcePriority() const {
  NOT_DESTROYED();
  PhysicalRect view_bounds = ViewRect();
  PhysicalRect object_bounds = PhysicalContentBoxRect();
  // TODO(japhet): Is this IgnoreTransforms correct? Would it be better to use
  // the visual rect (which has ancestor clips and transforms applied)? Should
  // we map to the top-level viewport instead of the current (sub) frame?
  object_bounds.Move(LocalToAbsolutePoint(PhysicalOffset(), kIgnoreTransforms));

  // The object bounds might be empty right now, so intersects will fail since
  // it doesn't deal with empty rects. Use PhysicalRect::Contains in that case.
  bool is_visible;
  if (!object_bounds.IsEmpty())
    is_visible = view_bounds.Intersects(object_bounds);
  else
    is_visible = view_bounds.Contains(object_bounds);

  PhysicalRect screen_rect;
  if (!object_bounds.IsEmpty()) {
    screen_rect = view_bounds;
    screen_rect.Intersect(object_bounds);
  }

  int screen_area = 0;
  if (!screen_rect.IsEmpty() && is_visible)
    screen_area = (screen_rect.Width() * screen_rect.Height()).ToInt();
  return ResourcePriority(
      is_visible ? ResourcePriority::kVisible : ResourcePriority::kNotVisible,
      screen_area);
}

void LayoutBox::LocationChanged() {
  NOT_DESTROYED();
  // The location may change because of layout of other objects. Should check
  // this object for paint invalidation.
  if (!NeedsLayout())
    SetShouldCheckForPaintInvalidation();
}

void LayoutBox::SizeChanged() {
  NOT_DESTROYED();
  SetScrollableAreaSizeChanged(true);
  // The size may change because of layout of other objects. Should check this
  // object for paint invalidation.
  if (!NeedsLayout())
    SetShouldCheckForPaintInvalidation();
  // In flipped blocks writing mode, our children can change physical location,
  // but their flipped location remains the same.
  if (HasFlippedBlocksWritingMode()) {
    if (ChildrenInline())
      SetSubtreeShouldDoFullPaintInvalidation();
    else
      SetSubtreeShouldCheckForPaintInvalidation();
  }
}

bool LayoutBox::IntersectsVisibleViewport() const {
  NOT_DESTROYED();
  LayoutView* layout_view = View();
  while (auto* owner = layout_view->GetFrame()->OwnerLayoutObject()) {
    layout_view = owner->View();
  }
  // If this is the outermost LayoutView then it will always intersect. (`rect`
  // will be the viewport in that case.)
  if (this == layout_view) {
    return true;
  }
  PhysicalRect rect = VisualOverflowRect();
  MapToVisualRectInAncestorSpace(layout_view, rect);
  return rect.Intersects(PhysicalRect(
      layout_view->GetFrameView()->GetScrollableArea()->VisibleContentRect()));
}

void LayoutBox::EnsureIsReadyForPaintInvalidation() {
  NOT_DESTROYED();
  LayoutBoxModelObject::EnsureIsReadyForPaintInvalidation();

  bool new_obscured = ComputeBackgroundIsKnownToBeObscured();
  if (BackgroundIsKnownToBeObscured() != new_obscured) {
    SetBackgroundIsKnownToBeObscured(new_obscured);
    SetBackgroundNeedsFullPaintInvalidation();
  }

  if (MayNeedPaintInvalidationAnimatedBackgroundImage() &&
      !BackgroundIsKnownToBeObscured()) {
    SetBackgroundNeedsFullPaintInvalidation();
    SetShouldDelayFullPaintInvalidation();
  }

  if (ShouldDelayFullPaintInvalidation() && IntersectsVisibleViewport()) {
    // Do regular full paint invalidation if the object with delayed paint
    // invalidation is on screen.
    ClearShouldDelayFullPaintInvalidation();
    DCHECK(ShouldDoFullPaintInvalidation());
  }
}

void LayoutBox::InvalidatePaint(const PaintInvalidatorContext& context) const {
  NOT_DESTROYED();
  BoxPaintInvalidator(*this, context).InvalidatePaint();
}

void LayoutBox::ClearPaintFlags() {
  NOT_DESTROYED();
  LayoutObject::ClearPaintFlags();

  if (auto* scrollable_area = GetScrollableArea()) {
    if (auto* scrollbar =
            DynamicTo<CustomScrollbar>(scrollable_area->HorizontalScrollbar()))
      scrollbar->ClearPaintFlags();
    if (auto* scrollbar =
            DynamicTo<CustomScrollbar>(scrollable_area->VerticalScrollbar()))
      scrollbar->ClearPaintFlags();
  }
}

PhysicalRect LayoutBox::OverflowClipRect(
    const PhysicalOffset& location,
    OverlayScrollbarClipBehavior overlay_scrollbar_clip_behavior) const {
  NOT_DESTROYED();
  PhysicalRect clip_rect;

  if (IsEffectiveRootScroller()) {
    // If this box is the effective root scroller, use the viewport clipping
    // rect since it will account for the URL bar correctly which the border
    // box does not. We can do this because the effective root scroller is
    // restricted such that it exactly fills the viewport. See
    // RootScrollerController::IsValidRootScroller()
    clip_rect = PhysicalRect(location, View()->ViewRect().size);
  } else {
    clip_rect = PhysicalBorderBoxRect();
    clip_rect.Contract(BorderOutsets());
    clip_rect.Move(location);

    // Videos need to be pre-snapped so that they line up with the
    // display_rect and can enable hardware overlays.
    // Embedded objects are always sized to fit the content rect, but they
    // could overflow by 1px due to pre-snapping. Adjust clip rect to
    // match pre-snapped box as a special case.
    if (IsVideo() || IsLayoutEmbeddedContent())
      clip_rect = LayoutReplaced::PreSnappedRectForPersistentSizing(clip_rect);

    if (HasNonVisibleOverflow()) {
      const auto overflow_clip = GetOverflowClipAxes();
      if (overflow_clip != kOverflowClipBothAxis) {
        ApplyVisibleOverflowToClipRect(overflow_clip, clip_rect);
      } else if (ShouldApplyOverflowClipMargin()) {
        switch (StyleRef().OverflowClipMargin()->GetReferenceBox()) {
          case StyleOverflowClipMargin::ReferenceBox::kBorderBox:
            clip_rect.Expand(BorderOutsets());
            break;
          case StyleOverflowClipMargin::ReferenceBox::kPaddingBox:
            break;
          case StyleOverflowClipMargin::ReferenceBox::kContentBox:
            clip_rect.Contract(PaddingOutsets());
            break;
        }
        clip_rect.Inflate(StyleRef().OverflowClipMargin()->GetMargin());
      }
    }
  }

  if (IsScrollContainer()) {
    // The additional gutters created by scrollbar-gutter don't occlude the
    // content underneath, so they should not be clipped out here.
    // See https://crbug.com/710214
    ExcludeScrollbars(clip_rect, overlay_scrollbar_clip_behavior,
                      kExcludeScrollbarGutter);
  }

  if (IsA<HTMLInputElement>(GetNode())) [[unlikely]] {
    // We only apply a clip to <input> buttons, and not regular <button>s.
    if (IsTextField() || IsInputButton()) {
      DCHECK(HasControlClip());
      PhysicalRect control_clip = PhysicalPaddingBoxRect();
      control_clip.Move(location);
      clip_rect.Intersect(control_clip);
    }
  } else if (IsMenuList()) [[unlikely]] {
    DCHECK(HasControlClip());
    PhysicalRect control_clip = PhysicalContentBoxRect();
    control_clip.Move(location);
    clip_rect.Intersect(control_clip);
  } else {
    DCHECK(!HasControlClip());
  }

  return clip_rect;
}

bool LayoutBox::HasControlClip() const {
  NOT_DESTROYED();
  if (IsTextField() || IsMenuList() || IsInputButton()) [[unlikely]] {
    return true;
  }
  return false;
}

void LayoutBox::ExcludeScrollbars(
    PhysicalRect& rect,
    OverlayScrollbarClipBehavior overlay_scrollbar_clip_behavior,
    ShouldIncludeScrollbarGutter include_scrollbar_gutter) const {
  NOT_DESTROYED();
  if (CanSkipComputeScrollbars())
    return;

  PhysicalBoxStrut scrollbars = ComputeScrollbarsInternal(
      kDoNotClampToContentBox, overlay_scrollbar_clip_behavior,
      include_scrollbar_gutter);
  rect.offset.top += scrollbars.top;
  rect.offset.left += scrollbars.left;
  rect.size.width -= scrollbars.HorizontalSum();
  rect.size.height -= scrollbars.VerticalSum();
  rect.size.ClampNegativeToZero();
}

PhysicalRect LayoutBox::ClipRect(const PhysicalOffset& location) const {
  NOT_DESTROYED();
  PhysicalRect clip_rect(location, Size());
  LayoutUnit width = Size().width;
  LayoutUnit height = Size().height;

  if (!StyleRef().ClipLeft().IsAuto()) {
    LayoutUnit c = ValueForLength(StyleRef().ClipLeft(), width);
    clip_rect.offset.left += c;
    clip_rect.size.width -= c;
  }

  if (!StyleRef().ClipRight().IsAuto()) {
    clip_rect.size.width -=
        width - ValueForLength(StyleRef().ClipRight(), width);
  }

  if (!StyleRef().ClipTop().IsAuto()) {
    LayoutUnit c = ValueForLength(StyleRef().ClipTop(), height);
    clip_rect.offset.top += c;
    clip_rect.size.height -= c;
  }

  if (!StyleRef().ClipBottom().IsAuto()) {
    clip_rect.size.height -=
        height - ValueForLength(StyleRef().ClipBottom(), height);
  }

  return clip_rect;
}

LayoutUnit LayoutBox::ContainingBlockLogicalHeightForRelPositioned() const {
  NOT_DESTROYED();
  DCHECK(IsRelPositioned());

  // TODO(ikilpatrick): This is resolving percentages against incorrectly if
  // the container is an inline.
  auto* cb = To<LayoutBoxModelObject>(Container());
  return ContainingBlockLogicalHeightForPositioned(cb) -
         cb->PaddingLogicalHeight();
}

LayoutUnit LayoutBox::ContainingBlockLogicalWidthForContent() const {
  NOT_DESTROYED();
  if (HasOverrideContainingBlockContentLogicalWidth())
    return OverrideContainingBlockContentLogicalWidth();

  LayoutBlock* cb = ContainingBlock();
  if (IsOutOfFlowPositioned())
    return cb->ClientLogicalWidth();
  return cb->AvailableLogicalWidth();
}

PhysicalOffset LayoutBox::OffsetFromContainerInternal(
    const LayoutObject* o,
    MapCoordinatesFlags mode) const {
  NOT_DESTROYED();
  DCHECK_EQ(o, Container());

  PhysicalOffset offset = PhysicalLocation();

  if (IsStickyPositioned() && !(mode & kIgnoreStickyOffset)) {
    offset += StickyPositionOffset();
  }

  if (o->IsScrollContainer())
    offset += OffsetFromScrollableContainer(o, mode & kIgnoreScrollOffset);

  if (NeedsAnchorPositionScrollAdjustment()) {
    offset += AnchorPositionScrollTranslationOffset();
  }

  return offset;
}

bool LayoutBox::HasInlineFragments() const {
  NOT_DESTROYED();
  return first_fragment_item_index_;
}

void LayoutBox::ClearFirstInlineFragmentItemIndex() {
  NOT_DESTROYED();
  CHECK(IsInLayoutNGInlineFormattingContext()) << *this;
  first_fragment_item_index_ = 0u;
}

void LayoutBox::SetFirstInlineFragmentItemIndex(wtf_size_t index) {
  NOT_DESTROYED();
  CHECK(IsInLayoutNGInlineFormattingContext()) << *this;
  DCHECK_NE(index, 0u);
  first_fragment_item_index_ = index;
}

void LayoutBox::InLayoutNGInlineFormattingContextWillChange(bool new_value) {
  NOT_DESTROYED();
  if (IsInLayoutNGInlineFormattingContext())
    ClearFirstInlineFragmentItemIndex();
}

bool LayoutBox::PhysicalFragmentList::MayHaveFragmentItems() const {
  return !IsEmpty() && front().IsInlineFormattingContext();
}

bool LayoutBox::PhysicalFragmentList::SlowHasFragmentItems() const {
  for (const PhysicalBoxFragment& fragment : *this) {
    if (fragment.HasItems())
      return true;
  }
  return false;
}

wtf_size_t LayoutBox::PhysicalFragmentList::IndexOf(
    const PhysicalBoxFragment& fragment) const {
  wtf_size_t index = 0;
  for (const auto& result : layout_results_) {
    if (&result->GetPhysicalFragment() == &fragment) {
      return index;
    }
    ++index;
  }
  return kNotFound;
}

bool LayoutBox::PhysicalFragmentList::Contains(
    const PhysicalBoxFragment& fragment) const {
  return IndexOf(fragment) != kNotFound;
}

void LayoutBox::AddMeasureLayoutResult(const LayoutResult* result) {
  // Ensure the given result is valid for the measure cache.
  if (result->Status() != LayoutResult::kSuccess) {
    return;
  }
  if (result->GetConstraintSpaceForCaching().CacheSlot() !=
      LayoutResultCacheSlot::kMeasure) {
    return;
  }
  DCHECK(
      To<PhysicalBoxFragment>(result->GetPhysicalFragment()).IsOnlyForNode());

  if (!measure_cache_) {
    measure_cache_ = MakeGarbageCollected<MeasureCache>();
  }
  // Clear out old measure results if we need non-simplifed layout.
  if (NeedsLayout() && !NeedsSimplifiedLayoutOnly()) {
    measure_cache_->Clear();
  }
  measure_cache_->Add(result);
}

void LayoutBox::SetCachedLayoutResult(const LayoutResult* result,
                                      wtf_size_t index) {
  NOT_DESTROYED();
  if (result->GetConstraintSpaceForCaching().CacheSlot() ==
      LayoutResultCacheSlot::kMeasure) {
    DCHECK(!result->GetPhysicalFragment().GetBreakToken());
    DCHECK(
        To<PhysicalBoxFragment>(result->GetPhysicalFragment()).IsOnlyForNode());
    DCHECK_EQ(index, 0u);
    // We don't early return here, when setting the "measure" result we also
    // set the "layout" result.
    if (measure_cache_) {
      measure_cache_->InvalidateItems();
    }
    AddMeasureLayoutResult(result);
    if (IsTableCell()) {
      To<LayoutTableCell>(this)->InvalidateLayoutResultCacheAfterMeasure();
    }
  } else {
    // We have a "layout" result, and we may need to clear the old "measure"
    // result if we needed non-simplified layout.
    if (NeedsLayout() && !NeedsSimplifiedLayoutOnly()) {
      if (measure_cache_) {
```