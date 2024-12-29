Response:
My thinking process to answer the request about `paint_property_tree_builder.cc` went something like this:

1. **Understand the Core Function:** The filename itself is highly indicative. "Paint Property Tree Builder" immediately tells me this code is responsible for constructing the data structure that describes how elements are painted. The "Tree" aspect implies a hierarchical relationship mirroring the DOM.

2. **Scan for Key Concepts:** I quickly scanned the provided code snippet for recurring terms and important data structures. Terms like "transform," "opacity," "clip," "filter," "scroll," "paint offset," "layout shift root," and "compositing" stood out. The `FragmentData` and `PaintProperties` classes were also prominent.

3. **Relate to Web Standards (HTML, CSS, JavaScript):**  I mentally linked the identified concepts to their counterparts in web technologies:
    * **Transforms:**  CSS `transform` property (e.g., `translate`, `rotate`, `scale`). JavaScript can manipulate these styles.
    * **Opacity:** CSS `opacity` property. JavaScript can change it.
    * **Clip:** CSS `clip` and `clip-path` properties.
    * **Filter:** CSS `filter` property (e.g., `blur`, `grayscale`).
    * **Scroll:**  Browser scrolling, CSS `overflow` property, scroll events in JavaScript.
    * **Paint Offset:**  Related to positioning and how elements are layered. Might be influenced by `position: relative` and `transform`.
    * **Layout Shift Root:**  Crucial for understanding Cumulative Layout Shift (CLS), a web performance metric. Certain CSS properties can make an element a layout shift root.
    * **Compositing:**  Browser optimization where parts of the page are rendered independently on the GPU. CSS properties can trigger compositing.

4. **Analyze Code Structure (Methods and Logic):** I looked at the methods within the `FragmentPaintPropertyTreeBuilder` and `PaintPropertyTreeBuilder` classes:
    * **`UpdateFor...` methods:** These clearly indicate the different aspects of an element's painting properties being processed (e.g., location, self, children).
    * **Conditional Logic:**  The `if` statements based on `Needs...` functions suggest that the builder intelligently decides which properties need updating based on the element's styles and state.
    * **`SetOnlyThisNeedsPaintPropertyUpdate()`:** This signals that a change requires the paint properties to be recalculated.
    * **Layout Shift Root Logic:** The code around `IsLayoutShiftRoot` points to the importance of this concept for performance and stability.
    * **Deferred Updates:** The `ScheduleDeferredTransformNodeUpdate` and `ScheduleDeferredOpacityNodeUpdate` functions suggest optimizations to avoid unnecessary recalculations.
    * **Direct Updates:** The `DirectlyUpdateTransformMatrix` and `DirectlyUpdateOpacityValue` further emphasize optimization strategies for common, performance-sensitive properties.

5. **Infer Functionality:** Based on the above analysis, I started to formulate the core functionalities:
    * Building the paint property tree.
    * Determining which properties need updates.
    * Handling different types of properties (transform, opacity, clip, etc.).
    * Optimizing updates.
    * Identifying layout shift roots.

6. **Relate Functionality to Web Technologies (with Examples):**  This is where I connected the dots and provided concrete examples:
    * **JavaScript:**  Changing styles via JavaScript triggers the builder to update.
    * **HTML:** The structure of the HTML affects the tree hierarchy.
    * **CSS:**  CSS properties directly determine the values in the paint property tree.

7. **Consider Logical Reasoning (Input/Output):**  I thought about scenarios and how the code would react:
    * **Input:** A change in CSS `transform`. **Output:** Update to the transform node in the paint property tree.
    * **Input:** Setting `position: fixed`. **Output:**  The element becomes a potential containing block, affecting paint offset calculations.

8. **Identify Potential User/Programming Errors:** I focused on common pitfalls:
    * **Performance:**  Excessive or unnecessary CSS changes can lead to frequent rebuilds, impacting performance.
    * **Layout Shifts:** Understanding which CSS properties create layout shift roots is crucial for avoiding CLS issues.

9. **Outline User Operations Leading to This Code:** I traced back how a user's actions could trigger the execution of this code:
    * Initial page load and rendering.
    * CSS style changes (via stylesheet or JavaScript).
    * User interactions (scrolling, resizing).
    * Animations and transitions.

10. **Synthesize the Summary:** Finally, I condensed the identified functionalities into a concise summary, highlighting the core role of the `paint_property_tree_builder.cc` file.

Throughout this process, I continually referred back to the code snippet to ensure my inferences were grounded in the actual implementation. The comments within the code were also helpful in understanding the intent behind certain logic. The fact that it was part 5 of 6 also hinted that it was a significant part of a larger paint pipeline.
好的，让我们来分析一下 `blink/renderer/core/paint/paint_property_tree_builder.cc` 文件的功能，并结合您提供的代码片段进行深入理解。

**核心功能归纳：**

`paint_property_tree_builder.cc` 的主要功能是 **构建和更新元素的 Paint Property Tree (绘制属性树)**。这个树形结构记录了影响元素绘制的关键属性，例如变换 (transform)、裁剪 (clip)、遮罩 (mask)、滤镜 (filter)、滚动 (scroll) 和偏移 (offset) 等。

更具体地说，它负责：

1. **确定哪些元素需要创建或更新绘制属性节点。** 这基于元素的样式、类型以及父元素的绘制属性。
2. **计算和设置各个绘制属性节点的值。** 例如，根据 CSS `transform` 属性计算变换矩阵，根据 `opacity` 属性设置透明度值。
3. **优化更新过程。**  例如，通过延迟更新或直接更新某些属性来避免不必要的重新计算。
4. **识别和处理布局偏移根 (Layout Shift Root)。** 这对于 Cumulative Layout Shift (CLS) 的计算至关重要。
5. **处理与分片 (fragmentation) 相关的绘制属性。**  例如，在多列布局或分页打印中。
6. **与合成 (compositing) 机制协同工作。**  确定哪些元素需要合成到独立的层中。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

这个文件是 Blink 渲染引擎的核心部分，它将 HTML 结构和 CSS 样式转化为最终的像素输出，并与 JavaScript 产生的动态效果交互。

* **HTML:**
    * **功能关系：**  HTML 定义了页面的结构，`paint_property_tree_builder.cc` 根据 HTML 元素的层级关系构建绘制属性树。
    * **举例：**  当 HTML 中新增一个 `<div>` 元素时，`paint_property_tree_builder.cc` 会为其创建一个对应的绘制属性节点（如果需要）。

* **CSS:**
    * **功能关系：** CSS 规则决定了元素的样式，而这些样式直接影响绘制属性树的构建和更新。`paint_property_tree_builder.cc` 会解析 CSS 属性（例如 `transform`, `opacity`, `clip-path` 等）并将其值写入绘制属性节点。
    * **举例：**
        * 当 CSS 中设置了 `div { transform: translateX(10px); }` 时，`paint_property_tree_builder.cc` 会计算出相应的变换矩阵并更新 `div` 元素的变换属性节点。
        * 当 CSS 中设置了 `img { opacity: 0.5; }` 时，`paint_property_tree_builder.cc` 会将 `img` 元素的透明度属性节点设置为 0.5。
        * CSS 中的 `position: fixed` 或包含 `transform` 的元素可能会被识别为布局偏移根，`paint_property_tree_builder.cc` 中的 `IsLayoutShiftRoot` 函数会进行判断。

* **JavaScript:**
    * **功能关系：** JavaScript 可以动态地修改元素的样式，这些修改会触发 `paint_property_tree_builder.cc` 重新计算和更新绘制属性树。
    * **举例：**
        * 当 JavaScript 代码执行 `element.style.transform = 'rotate(45deg)';` 时，`paint_property_tree_builder.cc` 会响应这个变化，重新计算旋转变换并更新元素的变换属性节点。
        * JavaScript 动画或过渡效果修改 CSS 属性时，也会驱动 `paint_property_tree_builder.cc` 不断更新绘制属性树，从而实现动画效果。

**逻辑推理（假设输入与输出）：**

假设输入一个 `LayoutBox` 对象，其 CSS 样式如下：

```css
.box {
  width: 100px;
  height: 100px;
  transform: translate(20px, 30px) rotate(10deg);
  opacity: 0.8;
  clip-path: circle(50px);
}
```

**假设输入：**  指向上述 `LayoutBox` 对象的指针。

**逻辑推理过程（代码片段中的体现）：**

* **`UpdateForObjectLocation`:** 可能会根据元素的布局位置更新 `paint_offset`。
* **`SetNeedsPaintPropertyUpdateIfNeeded`:**  由于样式发生了变化（存在 `transform`、`opacity`、`clip-path`），很可能会调用此函数标记需要更新绘制属性。
* **`UpdateTransform`:**  会根据 CSS `transform` 属性计算出平移和旋转的变换矩阵，并更新元素的变换属性节点。
* **`UpdateEffect`:** 可能会处理 `opacity` 属性，更新元素的特效属性节点。
* **`UpdateClipPathClip`:** 会根据 `clip-path` 属性生成裁剪路径，并更新元素的裁剪属性节点。
* **`IsLayoutShiftRoot`:**  可能会判断该元素是否是布局偏移根（例如，如果它有 transform 属性）。

**可能的输出（绘制属性树的部分节点信息）：**

* **Transform 节点:**  包含一个表示 `translate(20px, 30px) rotate(10deg)` 的变换矩阵。
* **Effect 节点:**  包含 `opacity: 0.8` 的信息。
* **Clip 节点:**  包含一个圆形裁剪路径的定义。

**用户或编程常见的使用错误：**

* **频繁触发重排和重绘的 JavaScript 动画：**  如果 JavaScript 代码在每一帧都修改元素的 `transform` 或其他影响绘制属性的样式，会导致 `paint_property_tree_builder.cc` 频繁运行，消耗大量资源，影响性能。
    * **例子：**  使用 `setInterval` 或 `requestAnimationFrame` 实现动画时，如果没有进行优化，可能会导致不必要的绘制属性更新。
* **不理解哪些 CSS 属性会触发新的合成层：**  某些 CSS 属性（例如 `transform`, `opacity`, `will-change` 等）可能会导致元素被提升到新的合成层。如果开发者不理解这种机制，可能会意外地创建过多的合成层，导致内存占用增加和性能下降。
* **过度使用 `will-change` 属性：**  `will-change` 提示浏览器元素可能会发生变化，但过度使用可能会导致浏览器提前分配资源，反而降低性能。
* **忽视布局偏移带来的性能影响：**  不合理的 CSS 样式或 JavaScript 操作可能导致页面元素在渲染过程中发生位置移动（布局偏移），这会影响用户体验，并且与 `paint_property_tree_builder.cc` 中布局偏移根的判断密切相关。

**用户操作如何一步步到达这里（作为调试线索）：**

1. **用户加载网页：** 浏览器开始解析 HTML 和 CSS。
2. **渲染引擎构建 DOM 树和 CSSOM 树。**
3. **布局计算 (Layout)：**  根据 DOM 树和 CSSOM 树计算每个元素在页面上的位置和大小。
4. **绘制属性树构建 (Paint Property Tree Building)：**  `paint_property_tree_builder.cc` 参与此阶段，遍历布局树，为需要绘制的元素构建绘制属性树。
5. **绘制 (Paint)：**  根据绘制属性树的信息，将元素绘制到屏幕上。
6. **用户交互或 JavaScript 动态修改：**
    * **滚动页面：**  可能会触发 `UpdateScrollAndScrollTranslation` 等函数。
    * **鼠标悬停或点击元素，触发 CSS 状态变化：**  导致样式改变，进而触发绘制属性的更新。
    * **JavaScript 修改元素样式或执行动画：**  直接触发 `paint_property_tree_builder.cc` 重新计算和更新绘制属性。
7. **合成 (Compositing)：** 如果某些元素被提升为合成层，会基于其绘制属性进行合成。

**代码片段的功能归纳：**

您提供的代码片段主要关注以下功能：

* **优化变换和透明度更新：**  通过 `RemovePendingTransformUpdate` 和 `RemovePendingOpacityUpdate` 来检查是否有待处理的变换或透明度更新，并标记元素需要更新绘制属性。
* **根据尺寸变化触发更新：**  当元素尺寸发生变化时，检查是否有需要根据尺寸进行更新的绘制属性（例如 `overflow-clip`, `clip`, `transform-origin` 等）。
* **处理反射效果：**  如果元素有反射效果，会标记需要更新滤镜效果节点。
* **更新偏移 (Paint Offset)：** `UpdateForObjectLocation` 函数负责更新元素的绘制偏移，并处理由于偏移变化可能导致的子树更新。
* **判断布局偏移根：** `IsLayoutShiftRoot` 函数判断当前元素是否是布局偏移根，考虑了 `transform`, `opacity`, `clip-path`, `position: fixed` 等因素。
* **更新自身绘制属性：** `UpdateForSelf` 函数负责更新元素自身的绘制属性，包括变换、旋转、缩放、偏移、裁剪、滤镜等。
* **更新子元素的绘制属性：** `UpdateForChildren` 函数负责处理子元素的绘制属性，例如内边框裁剪、溢出裁剪、透视、滚动和滚动变换等。
* **处理布局偏移根变化：** `UpdateLayoutShiftRootChanged` 函数记录布局偏移根状态的变化。
* **延迟更新优化：** `ScheduleDeferredTransformNodeUpdate` 和 `ScheduleDeferredOpacityNodeUpdate` 函数用于安排延迟执行的变换和透明度更新，以提高性能。
* **直接更新优化：** `DirectlyUpdateTransformMatrix` 和 `DirectlyUpdateOpacityValue` 函数提供了直接更新变换矩阵和透明度值的快速通道，避免了完整的绘制属性树重建。

总而言之，这段代码是 Chromium Blink 渲染引擎中负责管理元素绘制属性的核心模块之一，它连接了 HTML 结构、CSS 样式和 JavaScript 动态效果，最终影响着用户在浏览器中看到的页面内容。理解它的工作原理对于开发高性能的 Web 应用至关重要。

Prompt: 
```
这是目录为blink/renderer/core/paint/paint_property_tree_builder.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共6部分，请归纳一下它的功能

"""
te, we need to go ahead and do a regular transform
  // update so that the context (e.g.,
  // |translation_2d_to_layout_shift_root_delta|) is updated properly.
  // See: ../paint/README.md#Transform-update-optimization for more on
  // optimized transform updates
  if (object_.GetFrameView()->RemovePendingTransformUpdate(object_))
    object_.GetMutableForPainting().SetOnlyThisNeedsPaintPropertyUpdate();
  if (object_.GetFrameView()->RemovePendingOpacityUpdate(object_))
    object_.GetMutableForPainting().SetOnlyThisNeedsPaintPropertyUpdate();

  if (box.Size() == box.PreviousSize()) {
    return;
  }

  // The overflow clip paint property depends on the border box rect through
  // overflowClipRect(). The border box rect's size equals the frame rect's
  // size so we trigger a paint property update when the frame rect changes.
  if (NeedsOverflowClip(box) || NeedsInnerBorderRadiusClip(box) ||
      // The used value of CSS clip may depend on size of the box, e.g. for
      // clip: rect(auto auto auto -5px).
      NeedsCssClip(box) ||
      // Relative lengths (e.g., percentage values) in transform, perspective,
      // transform-origin, and perspective-origin can depend on the size of the
      // frame rect, so force a property update if it changes. TODO(pdr): We
      // only need to update properties if there are relative lengths.
      box.HasTransform() || NeedsPerspective(box) ||
      // CSS mask and clip-path comes with an implicit clip to the border box.
      box.HasMask() || box.HasClipPath() ||
      // Backdrop-filter's bounds use the border box rect.
      !box.StyleRef().BackdropFilter().IsEmpty()) {
    box.GetMutableForPainting().SetOnlyThisNeedsPaintPropertyUpdate();
  }

  // The filter generated for reflection depends on box size.
  if (box.HasReflection()) {
    DCHECK(box.HasLayer());
    box.Layer()->SetFilterOnEffectNodeDirty();
    box.GetMutableForPainting().SetOnlyThisNeedsPaintPropertyUpdate();
  }
}

void FragmentPaintPropertyTreeBuilder::UpdateForObjectLocation(
    std::optional<gfx::Vector2d>& paint_offset_translation) {
  context_.old_paint_offset = fragment_data_.PaintOffset();
  UpdatePaintOffset();
  UpdateForPaintOffsetTranslation(paint_offset_translation);

  PhysicalOffset paint_offset_delta =
      fragment_data_.PaintOffset() - context_.current.paint_offset;
  if (!paint_offset_delta.IsZero() &&
      !PrePaintDisableSideEffectsScope::IsDisabled()) {
    // Many paint properties depend on paint offset so we force an update of
    // the entire subtree on paint offset changes.
    full_context_.force_subtree_update_reasons |=
        PaintPropertyTreeBuilderContext::kSubtreeUpdateIsolationBlocked;
    object_.GetMutableForPainting().SetShouldCheckForPaintInvalidation();
    fragment_data_.SetPaintOffset(context_.current.paint_offset);

    if (object_.IsBox()) {
      // See PaintLayerScrollableArea::PixelSnappedBorderBoxSize() for the
      // reason of this.
      if (auto* scrollable_area = To<LayoutBox>(object_).GetScrollableArea())
        scrollable_area->PositionOverflowControls();
    }
  }

  if (paint_offset_translation)
    context_.current.paint_offset_root = &To<LayoutBoxModelObject>(object_);
}

static bool IsLayoutShiftRoot(const LayoutObject& object,
                              const FragmentData& fragment) {
  const auto* properties = fragment.PaintProperties();
  if (!properties)
    return false;
  if (IsA<LayoutView>(object))
    return true;
  for (const TransformPaintPropertyNode* transform :
       properties->AllCSSTransformPropertiesOutsideToInside()) {
    if (transform && IsLayoutShiftRootTransform(*transform))
      return true;
  }
  if (properties->ReplacedContentTransform())
    return true;
  if (properties->TransformIsolationNode())
    return true;
  if (auto* offset_translation = properties->PaintOffsetTranslation()) {
    if (offset_translation->RequiresCompositingForFixedPosition() &&
        // This is to keep the de facto CLS behavior with crrev.com/1036822.
        object.GetFrameView()->LayoutViewport()->HasOverflow()) {
      return true;
    }
  }
  if (properties->StickyTranslation()) {
    return true;
  }
  if (properties->AnchorPositionScrollTranslation()) {
    return true;
  }
  if (properties->OverflowClip())
    return true;
  return false;
}

void FragmentPaintPropertyTreeBuilder::UpdateForSelf() {
#if DCHECK_IS_ON()
  bool should_check_paint_under_invalidation =
      RuntimeEnabledFeatures::PaintUnderInvalidationCheckingEnabled() &&
      !PrePaintDisableSideEffectsScope::IsDisabled();
  std::optional<FindPaintOffsetNeedingUpdateScope> check_paint_offset;
  if (should_check_paint_under_invalidation) {
    check_paint_offset.emplace(object_, fragment_data_,
                               full_context_.is_actually_needed);
  }
#endif

  // This is not in FindObjectPropertiesNeedingUpdateScope because paint offset
  // can change without NeedsPaintPropertyUpdate.
  std::optional<gfx::Vector2d> paint_offset_translation;
  UpdateForObjectLocation(paint_offset_translation);
  if (&fragment_data_ == &object_.FirstFragment())
    SetNeedsPaintPropertyUpdateIfNeeded();

  if (properties_) {
    // Update of PaintOffsetTranslation is checked by
    // FindPaintOffsetNeedingUpdateScope.
    UpdatePaintOffsetTranslation(paint_offset_translation);
  }

#if DCHECK_IS_ON()
  std::optional<FindPropertiesNeedingUpdateScope> check_paint_properties;
  if (should_check_paint_under_invalidation) {
    bool force_subtree_update = full_context_.force_subtree_update_reasons;
    check_paint_properties.emplace(object_, fragment_data_,
                                   force_subtree_update);
  }
#endif

  if (properties_) {
    UpdateStickyTranslation();
    UpdateAnchorPositionScrollTranslation();
    if (object_.IsSVGChild()) {
      // TODO(crbug.com/1278452): Merge SVG handling into the primary codepath.
      UpdateTransformForSVGChild(full_context_.direct_compositing_reasons);
    } else {
      UpdateTranslate();
      UpdateRotate();
      UpdateScale();
      UpdateOffset();
      UpdateTransform();
    }
    UpdateElementCaptureEffect();
    UpdateViewTransitionSubframeRootEffect();

    // When layered capture is enabled (see the inverse condition below), the
    // effects (clip/clip-path/opacity/mask/filter) are rendered in an ancestor
    // of the view transition capture. The corresponding CSS is copied to the
    // view-transition pseudo-elements instead of being captured into the
    // texture as content.

    const bool delegate_effects_to_view_transition = ViewTransitionUtils::
        ShouldDelegateEffectsAndBoxDecorationsToViewTransitionGroup(object_);
    if (!delegate_effects_to_view_transition) {
      UpdateViewTransitionEffect();
      UpdateViewTransitionClip();
    }
    UpdateClipPathClip();
    UpdateEffect();
    UpdateCssClip();
    UpdateFilter();

    // See comment above in inverse condition.
    if (delegate_effects_to_view_transition) {
      UpdateViewTransitionEffect();
      UpdateViewTransitionClip();
    }
    UpdateOverflowControlsClip();
    UpdateBackgroundClip();
  } else if (!object_.IsAnonymous()) {
    // 3D rendering contexts follow the DOM ancestor chain, so
    // flattening should apply regardless of presence of transform.
    context_.rendering_context_id = 0;
    context_.should_flatten_inherited_transform = true;
  }
  UpdateLocalBorderBoxContext();
  UpdateLayoutShiftRootChanged(IsLayoutShiftRoot(object_, fragment_data_));

  // For LayoutView, additional_offset_to_layout_shift_root_delta applies to
  // neither itself nor descendants. For other layout shift roots, we clear the
  // delta at the end of UpdateForChildren() because the delta still applies to
  // the object itself. Same for translation_2d_to_layout_shift_delta and
  // scroll_offset_to_layout_shift_root_delta.
  if (IsA<LayoutView>(object_)) {
    context_.current.additional_offset_to_layout_shift_root_delta =
        PhysicalOffset();
    context_.translation_2d_to_layout_shift_root_delta = gfx::Vector2dF();
    context_.current.scroll_offset_to_layout_shift_root_delta =
        gfx::Vector2dF();
  }
}

void FragmentPaintPropertyTreeBuilder::UpdateForChildren() {
#if DCHECK_IS_ON()
  // Will be used though a reference by check_paint_offset, so it's declared
  // here to out-live check_paint_offset. It's false because paint offset
  // should not change during this function.
  const bool needs_paint_offset_update = false;
  std::optional<FindPaintOffsetNeedingUpdateScope> check_paint_offset;
  std::optional<FindPropertiesNeedingUpdateScope> check_paint_properties;
  if (RuntimeEnabledFeatures::PaintUnderInvalidationCheckingEnabled() &&
      !PrePaintDisableSideEffectsScope::IsDisabled()) {
    check_paint_offset.emplace(object_, fragment_data_,
                               needs_paint_offset_update);
    bool force_subtree_update = full_context_.force_subtree_update_reasons;
    check_paint_properties.emplace(object_, fragment_data_,
                                   force_subtree_update);
  }
#endif

  // Child transform nodes should not inherit backface visibility if the parent
  // transform node preserves 3d. This is before UpdatePerspective() because
  // perspective itself doesn't affect backface visibility inheritance.
  context_.can_inherit_backface_visibility =
      context_.should_flatten_inherited_transform;

  if (properties_) {
    UpdateInnerBorderRadiusClip();
    UpdateOverflowClip();
    UpdatePerspective();
    UpdateReplacedContentTransform();
    UpdateScrollAndScrollTranslation();
    UpdateTransformIsolationNode();
    UpdateEffectIsolationNode();
    UpdateClipIsolationNode();
  }
  UpdateOutOfFlowContext();

  bool is_layout_shift_root = IsLayoutShiftRoot(object_, fragment_data_);
  UpdateLayoutShiftRootChanged(is_layout_shift_root);
  if (full_context_.was_layout_shift_root || is_layout_shift_root) {
    // A layout shift root (e.g. with mere OverflowClip) may have non-zero
    // paint offset. Exclude the layout shift root's paint offset delta from
    // additional_offset_to_layout_shift_root_delta.
    context_.current.additional_offset_to_layout_shift_root_delta =
        context_.old_paint_offset - fragment_data_.PaintOffset();
    context_.translation_2d_to_layout_shift_root_delta = gfx::Vector2dF();
    // Don't reset scroll_offset_to_layout_shift_root_delta if this object has
    // scroll translation because we need to propagate the delta to descendants.
    if (!properties_ || !properties_->ScrollTranslation()) {
      context_.current.scroll_offset_to_layout_shift_root_delta =
          gfx::Vector2dF();
      context_.current.pending_scroll_anchor_adjustment = gfx::Vector2dF();
    }
  }

#if DCHECK_IS_ON()
  if (properties_)
    properties_->Validate();
#endif
}

void FragmentPaintPropertyTreeBuilder::UpdateLayoutShiftRootChanged(
    bool is_layout_shift_root) {
  if (is_layout_shift_root != full_context_.was_layout_shift_root) {
    context_.current.layout_shift_root_changed = true;
  } else if (is_layout_shift_root && full_context_.was_layout_shift_root) {
    context_.current.layout_shift_root_changed = false;
  }
}

}  // namespace

void PaintPropertyTreeBuilder::InitPaintProperties() {
  bool needs_paint_properties =
      ObjectTypeMightNeedPaintProperties() &&
      (NeedsPaintOffsetTranslation(object_, context_.direct_compositing_reasons,
                                   context_.container_for_fixed_position,
                                   context_.painting_layer) ||
       NeedsStickyTranslation(object_) ||
       NeedsAnchorPositionScrollTranslation(object_) ||
       NeedsTranslate(object_, context_.direct_compositing_reasons) ||
       NeedsRotate(object_, context_.direct_compositing_reasons) ||
       NeedsScale(object_, context_.direct_compositing_reasons) ||
       NeedsOffset(object_, context_.direct_compositing_reasons) ||
       NeedsTransform(object_, context_.direct_compositing_reasons) ||
       NeedsEffectIgnoringClipPath(object_,
                                   context_.direct_compositing_reasons) ||
       NeedsClipPathClipOrMask(object_) ||
       NeedsTransformForSVGChild(object_,
                                 context_.direct_compositing_reasons) ||
       NeedsFilter(object_, context_) || NeedsCssClip(object_) ||
       NeedsBackgroundClip(object_) || NeedsInnerBorderRadiusClip(object_) ||
       NeedsOverflowClip(object_) || NeedsPerspective(object_) ||
       NeedsReplacedContentTransform(object_) ||
       NeedsScrollAndScrollTranslation(object_,
                                       context_.direct_compositing_reasons));

  // If the object is a text, none of the above function should return true.
  DCHECK(!needs_paint_properties || !object_.IsText());

  FragmentData& fragment = GetFragmentData();
  if (const auto* properties = fragment.PaintProperties()) {
    if (const auto* translation = properties->PaintOffsetTranslation()) {
      // If there is a paint offset translation, it only causes a net change
      // in additional_offset_to_layout_shift_root_delta by the amount the
      // paint offset translation changed from the prior frame. To implement
      // this, we record a negative offset here, and then re-add it in
      // UpdatePaintOffsetTranslation. The net effect is that the value
      // of additional_offset_to_layout_shift_root_delta is the difference
      // between the old and new paint offset translation.
      context_.fragment_context
          .pending_additional_offset_to_layout_shift_root_delta =
          -PhysicalOffset::FromVector2dFRound(translation->Get2dTranslation());
    }
    gfx::Vector2dF translation2d;
    for (const TransformPaintPropertyNode* transform :
         properties->AllCSSTransformPropertiesOutsideToInside()) {
      if (transform) {
        if (IsLayoutShiftRootTransform(*transform)) {
          translation2d = gfx::Vector2dF();
          break;
        }
        translation2d += transform->Get2dTranslation();
      }
    }
    context_.fragment_context.translation_2d_to_layout_shift_root_delta -=
        translation2d;
  }

  if (needs_paint_properties) {
    fragment.EnsureId();
    fragment.EnsurePaintProperties();
  } else if (auto* properties = fragment.PaintProperties()) {
    if (properties->HasTransformNode()) {
      UpdatePropertyChange(properties_changed_.transform_changed,
                           PaintPropertyChangeType::kNodeAddedOrRemoved);
      properties_changed_.transform_change_is_scroll_translation_only = false;
    }
    if (properties->HasClipNode()) {
      UpdatePropertyChange(properties_changed_.clip_changed,
                           PaintPropertyChangeType::kNodeAddedOrRemoved);
    }
    if (properties->HasEffectNode()) {
      UpdatePropertyChange(properties_changed_.effect_changed,
                           PaintPropertyChangeType::kNodeAddedOrRemoved);
    }
    if (properties->Scroll()) {
      UpdatePropertyChange(properties_changed_.scroll_changed,
                           PaintPropertyChangeType::kNodeAddedOrRemoved);
    }
    fragment.ClearPaintProperties();
  }

  if (object_.IsSVGHiddenContainer()) {
    // SVG resources are painted within one or more other locations in the
    // SVG during paint, and hence have their own independent paint property
    // trees, paint offset, etc.
    context_.fragment_context = PaintPropertyTreeBuilderFragmentContext();
    context_.has_svg_hidden_container_ancestor = true;

    PaintPropertyTreeBuilderFragmentContext& fragment_context =
        context_.fragment_context;
    fragment_context.current.paint_offset_root =
        fragment_context.absolute_position.paint_offset_root =
            fragment_context.fixed_position.paint_offset_root = &object_;

    object_.GetMutableForPainting().FragmentList().Shrink(1);
  }

  if (object_.HasLayer()) {
    To<LayoutBoxModelObject>(object_).Layer()->SetIsUnderSVGHiddenContainer(
        context_.has_svg_hidden_container_ancestor);
  }
}

FragmentData& PaintPropertyTreeBuilder::GetFragmentData() const {
  if (pre_paint_info_) {
    CHECK(pre_paint_info_->fragment_data);
    return *pre_paint_info_->fragment_data;
  }
  return object_.GetMutableForPainting().FirstFragment();
}

void PaintPropertyTreeBuilder::UpdateFragmentData() {
  FragmentData& fragment = GetFragmentData();
  if (IsInNGFragmentTraversal()) {
    context_.fragment_context.current.fragmentainer_idx =
        pre_paint_info_->fragmentainer_idx;
  } else {
    DCHECK_EQ(&fragment, &object_.FirstFragment());
    const FragmentDataList& fragment_list =
        object_.GetMutableForPainting().FragmentList();
    wtf_size_t old_fragment_count = fragment_list.size();
    object_.GetMutableForPainting().FragmentList().Shrink(1);

    if (context_.fragment_context.current.fragmentainer_idx == WTF::kNotFound) {
      // We're not fragmented, but we may have been previously. Reset the
      // fragmentainer index.
      fragment.SetFragmentID(0);

      if (old_fragment_count > 1u) {
        object_.GetMutableForPainting().FragmentCountChanged();
      }
    } else {
      // We're inside monolithic content, but further out there's a
      // fragmentation context. Keep the fragmentainer index, so that the
      // contents end up in the right one.
      fragment.SetFragmentID(
          context_.fragment_context.current.fragmentainer_idx);
    }
  }
}

bool PaintPropertyTreeBuilder::ObjectTypeMightNeedPaintProperties() const {
  return !object_.IsText() && (object_.IsBoxModelObject() || object_.IsSVG());
}

void PaintPropertyTreeBuilder::UpdatePaintingLayer() {
  if (object_.HasLayer() &&
      To<LayoutBoxModelObject>(object_).HasSelfPaintingLayer()) {
    context_.painting_layer = To<LayoutBoxModelObject>(object_).Layer();
  } else if (object_.IsInlineRubyText()) {
    // Physical fragments and fragment items for ruby-text boxes are not
    // managed by inline parents.
    context_.painting_layer = object_.PaintingLayer();
  }
  DCHECK(context_.painting_layer == object_.PaintingLayer());
}

void PaintPropertyTreeBuilder::UpdateForSelf() {
  // These are not inherited from the parent context but calculated here.
  context_.direct_compositing_reasons =
      CompositingReasonFinder::DirectReasonsForPaintProperties(
          object_, context_.container_for_fixed_position);
  if (const auto* box = DynamicTo<LayoutBox>(object_)) {
    box->GetMutableForPainting().UpdateBackgroundPaintLocation();
    if (auto* scrollable_area = box->GetScrollableArea()) {
      bool force_prefer_compositing =
          CompositingReasonFinder::ShouldForcePreferCompositingToLCDText(
              object_, context_.direct_compositing_reasons);
      context_.composited_scrolling_preference = static_cast<unsigned>(
          force_prefer_compositing ? CompositedScrollingPreference::kPreferred
          : scrollable_area->PrefersNonCompositedScrolling()
              ? CompositedScrollingPreference::kNotPreferred
              : CompositedScrollingPreference::kDefault);
    }
  }

  if (Platform::Current()->IsLowEndDevice()) {
    // Don't composite "trivial" 3D transforms such as translateZ(0).
    // These transforms still force comosited scrolling (see above).
    context_.direct_compositing_reasons &=
        ~CompositingReason::kTrivial3DTransform;
  }

  if (context_.fragment_context
          .self_or_ancestor_participates_in_view_transition &&
      object_.StyleRef().HasClipPath()) {
    context_.direct_compositing_reasons |=
        CompositingReason::kViewTransitionElementDescendantWithClipPath;
  }

  context_.was_layout_shift_root =
      IsLayoutShiftRoot(object_, object_.FirstFragment());

  if (IsA<LayoutView>(object_)) {
    UpdateGlobalMainThreadRepaintReasonsForScroll();
  }

  context_.old_scroll_offset = gfx::Vector2dF();
  if (const auto* properties = object_.FirstFragment().PaintProperties()) {
    if (const auto* old_scroll_translation = properties->ScrollTranslation()) {
      DCHECK(context_.was_layout_shift_root);
      context_.old_scroll_offset = old_scroll_translation->Get2dTranslation();
    }
  }

  // Resolve the current composited clip path animation status. This is needed
  // to determine whether we need to initialize paint properties for this
  // object.
  const bool is_in_fragment_container =
      pre_paint_info_ &&
      pre_paint_info_->fragmentainer_is_oof_containing_block &&
      IsA<LayoutBox>(object_) &&
      (To<LayoutBox>(object_).PhysicalFragmentCount() > 1);
  ClipPathClipper::ResolveClipPathStatus(object_, is_in_fragment_container);

  UpdatePaintingLayer();
  UpdateFragmentData();
  InitPaintProperties();

  FragmentPaintPropertyTreeBuilder builder(object_, pre_paint_info_, context_,
                                           GetFragmentData());
  builder.UpdateForSelf();
  properties_changed_.Merge(builder.PropertiesChanged());

  if (!PrePaintDisableSideEffectsScope::IsDisabled()) {
    object_.GetMutableForPainting()
        .SetShouldAssumePaintOffsetTranslationForLayoutShiftTracking(false);
  }
}

void PaintPropertyTreeBuilder::UpdateGlobalMainThreadRepaintReasonsForScroll() {
  DCHECK(IsA<LayoutView>(object_));

  if (object_.GetFrameView()
          ->RequiresMainThreadScrollingForBackgroundAttachmentFixed()) {
    context_.requires_main_thread_for_background_attachment_fixed = true;
  }

  if (auto* properties = object_.FirstFragment().PaintProperties()) {
    if (auto* scroll = properties->Scroll()) {
      if (scroll->RequiresMainThreadForBackgroundAttachmentFixed() !=
          context_.requires_main_thread_for_background_attachment_fixed) {
        // The changed requires_main_thread_for_background_attachment_fixed
        // needs to propagate to all scroll nodes in this view.
        context_.force_subtree_update_reasons |=
            PaintPropertyTreeBuilderContext::kSubtreeUpdateIsolationPiercing;
      }
    }
  }
}

void PaintPropertyTreeBuilder::UpdateForChildren() {
  if (!ObjectTypeMightNeedPaintProperties())
    return;

  // For now, only consider single fragment elements as possible isolation
  // boundaries.
  // TODO(crbug.com/890932): See if this is needed.
  bool is_isolated = true;
  FragmentPaintPropertyTreeBuilder builder(object_, pre_paint_info_, context_,
                                           GetFragmentData());
  // The element establishes an isolation boundary if it has isolation nodes
  // before and after updating the children. In other words, if it didn't have
  // isolation nodes previously then we still want to do a subtree walk. If it
  // now doesn't have isolation nodes, then of course it is also not isolated.
  is_isolated &= builder.HasIsolationNodes();
  builder.UpdateForChildren();
  is_isolated &= builder.HasIsolationNodes();

  properties_changed_.Merge(builder.PropertiesChanged());

  if (object_.CanContainAbsolutePositionObjects())
    context_.container_for_absolute_position = &object_;
  if (object_.CanContainFixedPositionObjects())
    context_.container_for_fixed_position = &object_;

  if (properties_changed_.Max() >=
          PaintPropertyChangeType::kNodeAddedOrRemoved ||
      object_.SubtreePaintPropertyUpdateReasons() !=
          static_cast<unsigned>(SubtreePaintPropertyUpdateReason::kNone)) {
    // Force a piercing subtree update if the scroll tree hierarchy changes
    // because the scroll tree does not have isolation nodes and non-piercing
    // updates can fail to update scroll descendants.
    if (properties_changed_.scroll_changed >=
            PaintPropertyChangeType::kNodeAddedOrRemoved ||
        AreSubtreeUpdateReasonsIsolationPiercing(
            object_.SubtreePaintPropertyUpdateReasons())) {
      context_.force_subtree_update_reasons |=
          PaintPropertyTreeBuilderContext::kSubtreeUpdateIsolationPiercing;
    } else {
      context_.force_subtree_update_reasons |=
          PaintPropertyTreeBuilderContext::kSubtreeUpdateIsolationBlocked;
    }
  }

  if (properties_changed_.transform_changed >
          (properties_changed_.transform_change_is_scroll_translation_only
               ? PaintPropertyChangeType::kChangedOnlySimpleValues
               : PaintPropertyChangeType::kUnchanged) ||
      properties_changed_.clip_changed > PaintPropertyChangeType::kUnchanged ||
      properties_changed_.scroll_changed >
          PaintPropertyChangeType::kUnchanged) {
    object_.GetFrameView()->SetIntersectionObservationState(
        LocalFrameView::kDesired);
  }

  if (is_isolated) {
    context_.force_subtree_update_reasons &=
        ~PaintPropertyTreeBuilderContext::kSubtreeUpdateIsolationBlocked;
  }
}

void PaintPropertyTreeBuilder::UpdateForPageBorderBox(
    const PhysicalBoxFragment& page_container) {
  const PhysicalBoxFragment& page_border_box = *pre_paint_info_->box_fragment;
  DCHECK_EQ(page_border_box.GetBoxType(), PhysicalFragment::kPageBorderBox);

  // Since the page border box fragment is responsible for @page borders and
  // other decorations, in addition to the document background, it needs to be
  // in the coordinate system of paginated layout.
  float scale = TargetScaleForPage(page_container);

  PhysicalRect target_content_rect = page_border_box.ContentRect();
  // Scale to the coordinate system of the target (e.g. paper).
  target_content_rect.Scale(scale);
  // The offset, on the other hand, is already in the coordinate system of
  // the target.
  PhysicalOffset page_border_box_offset = pre_paint_info_->paint_offset;
  target_content_rect.offset += page_border_box_offset;
  gfx::Transform matrix =
      gfx::Transform::MakeTranslation(gfx::Vector2dF(page_border_box_offset));
  matrix.Scale(scale);
  TransformPaintPropertyNode::State transform_state{{matrix}};

  PaintPropertyTreeBuilderFragmentContext& fragment_context =
      context_.fragment_context;
  FragmentData& fragment_data = object_.GetMutableForPainting().FirstFragment();
  fragment_data.EnsurePaintProperties().UpdateTransform(
      *fragment_context.current.transform, std::move(transform_state));
  fragment_data.SetLocalBorderBoxProperties(PropertyTreeStateOrAlias(
      *fragment_data.PaintProperties()->Transform(),
      *fragment_context.current.clip, *fragment_context.current_effect));
}

bool PaintPropertyTreeBuilder::ScheduleDeferredTransformNodeUpdate(
    LayoutObject& object) {
  if (CanDoDeferredTransformNodeUpdate(object)) {
    object.GetFrameView()->AddPendingTransformUpdate(object);
    return true;
  }
  return false;
}

bool PaintPropertyTreeBuilder::ScheduleDeferredOpacityNodeUpdate(
    LayoutObject& object) {
  if (CanDoDeferredOpacityNodeUpdate(object)) {
    object.GetFrameView()->AddPendingOpacityUpdate(object);
    return true;
  }
  return false;
}

// Fast-path for directly updating transforms. Returns true if successful. This
// is similar to |FragmentPaintPropertyTreeBuilder::UpdateIndividualTransform|.
void PaintPropertyTreeBuilder::DirectlyUpdateTransformMatrix(
    const LayoutObject& object) {
  DCHECK(CanDoDeferredTransformNodeUpdate(object));

  auto& box = To<LayoutBox>(object);
  const PhysicalRect reference_box = ComputeReferenceBox(box);
  FragmentData* fragment_data = &object.GetMutableForPainting().FirstFragment();
  auto* properties = fragment_data->PaintProperties();
  auto* transform = properties->Transform();
  auto transform_and_origin = TransformAndOriginState(
      box, reference_box,
      [](const LayoutBox& box, const PhysicalRect& reference_box,
         gfx::Transform& matrix) {
        const ComputedStyle& style = box.StyleRef();
        style.ApplyTransform(
            matrix, &box, reference_box,
            ComputedStyle::kIncludeTransformOperations,
            ComputedStyle::kExcludeTransformOrigin,
            ComputedStyle::kExcludeMotionPath,
            ComputedStyle::kExcludeIndependentTransformProperties);
      });

  TransformPaintPropertyNode::AnimationState animation_state;
  animation_state.is_running_animation_on_compositor =
      box.StyleRef().IsRunningTransformAnimationOnCompositor();
  auto effective_change_type = properties->DirectlyUpdateTransformAndOrigin(
      std::move(transform_and_origin), animation_state);
  DirectlyUpdateCcTransform(*transform, object, effective_change_type);

  if (effective_change_type > PaintPropertyChangeType::kUnchanged) {
    object.GetFrameView()->SetIntersectionObservationState(
        LocalFrameView::kDesired);
  }

  if (effective_change_type >=
      PaintPropertyChangeType::kChangedOnlySimpleValues) {
    object.GetFrameView()->SetPaintArtifactCompositorNeedsUpdate();
  }

  PaintPropertiesChangeInfo properties_changed{
      .transform_changed = effective_change_type,
      .transform_change_is_scroll_translation_only = false,
  };
  CullRectUpdater::PaintPropertiesChanged(object, properties_changed);
}

void PaintPropertyTreeBuilder::DirectlyUpdateOpacityValue(
    const LayoutObject& object) {
  DCHECK(CanDoDeferredOpacityNodeUpdate(object));
  const ComputedStyle& style = object.StyleRef();

  EffectPaintPropertyNode::AnimationState animation_state;
  animation_state.is_running_opacity_animation_on_compositor =
      style.IsRunningOpacityAnimationOnCompositor();
  animation_state.is_running_backdrop_filter_animation_on_compositor =
      style.IsRunningBackdropFilterAnimationOnCompositor();

  FragmentData* fragment_data = &object.GetMutableForPainting().FirstFragment();
  auto* properties = fragment_data->PaintProperties();
  auto effective_change_type =
      properties->DirectlyUpdateOpacity(style.Opacity(), animation_state);
  // If we have simple value change, which means opacity, we should try to
  // directly update it on the PaintArtifactCompositor in order to avoid
  // needing to run the property tree builder at all.
  DirectlyUpdateCcOpacity(object, *properties, effective_change_type);

  if (effective_change_type >=
      PaintPropertyChangeType::kChangedOnlySimpleValues) {
    object.GetFrameView()->SetPaintArtifactCompositorNeedsUpdate();
  }
}

void PaintPropertyTreeBuilder::IssueInvalidationsAfterUpdate() {
  // We need to update property tree states of paint chunks.
  auto max_change = properties_changed_.Max();
  if (max_change >= PaintPropertyChangeType::kNodeAddedOrRemoved) {
    context_.painting_layer->SetNeedsRepaint();
    if (object_.IsDocumentElement()) {
      // View background painting depends on existence of the document element's
      // paint properties (see callsite of ViewPainter::PaintRootGroup()).
      // Invalidate view background display item clients.
      // SetBackgroundNeedsFullPaintInvalidation() won't work here because we
      // have already walked the LayoutView in PrePaintTreeWalk.
      LayoutView* layout_view = object_.View();
      layout_view->Layer()->SetNeedsRepaint();
      auto reason = PaintInvalidationReason::kBackground;
      static_cast<const DisplayItemClient*>(layout_view)->Invalidate(reason);
      if (auto* scrollable_area = layout_view->GetScrollableArea()) {
        scrollable_area->GetScrollingBackgroundDisplayItemClient().Invalidate(
            reason);
      }
    }
  }

  if (max_change > PaintPropertyChangeType::kChangedOnlyCompositedValues) {
    object_.GetFrameView()->SetPaintArtifactCompositorNeedsUpdate();
  }

  CullRectUpdater::PaintPropertiesChanged(object_, properties_changed_);
}

bool PaintPropertyTreeBuilder::CanDoDeferredTransformNodeUpdate(
    const LayoutObject& object) {
  // If we already need a full update, do not do the direct update.
  if (object.NeedsPaintPropertyUpdate() ||
      object.DescendantNeedsPaintPropertyUpdate()) {
    return false;
  }

  // SVG transforms use a different codepath (see:
  // |FragmentPaintPropertyTreeBuilder::UpdateTransformForSVGChild|).
  if (object.IsSVGChild())
    return false;

  // Only boxes have transform values (see:
  // |FragmentPaintPropertyTreeBuilder::UpdateIndividualTransform|).
  if (!object.IsBox())
    return false;

  // This fast path does not support iterating over each fragment, so do not
  // run the fast path in the presence of fragmentation.
  if (object.IsFragmented()) {
    return false;
  }

  auto* properties = object.FirstFragment().PaintProperties();
  // Cannot directly update properties if they have not been created yet.
  if (!properties || !properties->Transform())
    return false;

  return true;
}

bool PaintPropertyTreeBuilder::CanDoDeferredOpacityNodeUpdate(
    const LayoutObject& object) {
  // If we already need a full update, do not do the direct update.
  if (object.NeedsPaintPropertyUpdate() ||
      object.DescendantNeedsPaintPropertyUpdate()) {
    return false;
  }

  // In some cases where we need to remove the update, objects that are not
  // boxes can cause a bug. (See SetNeedsPaintPropertyUpdateIfNeeded)
  if (!ob
"""


```