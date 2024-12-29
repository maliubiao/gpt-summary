Response:
The user wants a summary of the functionality of the provided C++ code snippet from the Chromium Blink engine. They also want to know how it relates to web technologies like JavaScript, HTML, and CSS, including examples. Additionally, they're interested in logical reasoning with hypothetical inputs and outputs, common user/programming errors, debugging strategies, and how this part fits into the overall file.

Here's a plan:

1. **Identify the core purpose:** Analyze the code to understand its main function. It seems to be about updating paint property trees for layout objects during the rendering process.
2. **Break down functionalities:**  List the key actions performed by the code, such as updating effect, clip, transform properties, and handling different types of clips (mask, CSS, clip-path, overflow, border-radius).
3. **Relate to web technologies:**  Explain how each functionality connects to CSS properties (opacity, blend-mode, filters, masks, clip-path, overflow, border-radius), HTML elements (div, svg, replaced elements), and how JavaScript might trigger changes leading to these updates.
4. **Hypothetical input/output:** Create scenarios with CSS styles and HTML structures and explain how this code would process them, focusing on the changes to paint property nodes.
5. **Common errors:** Identify potential issues like incorrect CSS syntax, conflicting properties, or misunderstandings of how compositing works.
6. **User actions and debugging:** Trace back user interactions (scrolling, CSS changes, animations) that might lead to the execution of this code and suggest debugging techniques.
7. **Context within the file:** Summarize the role of this specific code block within the larger `paint_property_tree_builder.cc` file. It's responsible for updating properties of a single fragment.
这是 `blink/renderer/core/paint/paint_property_tree_builder.cc` 文件的一部分，主要负责构建和更新渲染对象的**绘制属性树 (Paint Property Tree)** 中的节点信息。这个阶段专注于处理**单个渲染片段 (Fragment)** 的绘制属性更新。

概括来说，这段代码的功能是：

**为给定的渲染对象片段 (Fragment)，根据其样式和布局信息，更新其在绘制属性树中对应的 Effect、Clip 等节点的状态。**

更具体地说，它会检查和更新以下属性：

* **Effect (效果):**  处理 `opacity`, `blend-mode`, `filter`, `backdrop-filter`, `mask` 等 CSS 属性产生的视觉效果。
* **Clip (裁剪):**  处理各种类型的裁剪，包括 `clip-path`, `mask-clip`, `clip` 属性以及由于 `overflow` 和 `border-radius` 产生的裁剪。
* **View Transition (视图过渡):** 处理与视图过渡动画相关的效果和裁剪。
* **Element Capture (元素捕获):** 处理用于元素捕获的效果。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这段代码是浏览器渲染引擎的核心部分，直接响应 HTML 结构和 CSS 样式，并为后续的渲染和合成步骤提供数据。JavaScript 可以通过修改 DOM 结构或 CSS 样式来间接影响这里的逻辑。

* **CSS 和 Effect:**
    * **例子:** 当 CSS 中设置了 `opacity: 0.5;`，代码中的 `UpdateEffect()` 函数会读取这个值，并更新 `EffectPaintPropertyNode` 的 `opacity` 属性。
    * **例子:**  如果 CSS 中设置了 `filter: blur(5px);`，`UpdateFilter()` 函数会解析这个滤镜，并更新 `EffectPaintPropertyNode` 的 `filter` 属性，可能还会创建一个 `ClipPaintPropertyNode` 用于处理滤镜带来的裁剪。
    * **例子:**  CSS 的 `mask-image` 属性会导致 `UpdateEffect()` 函数中创建或更新 `MaskPaintPropertyNode` 和 `ClipPaintPropertyNode` 来实现遮罩效果。
    * **例子:**  `backdrop-filter: blur(10px);` 会在 `UpdateEffect()` 中生成 `BackdropFilterInfo` 并关联到 `EffectPaintPropertyNode`。
    * **例子:**  `mix-blend-mode: multiply;` 会影响 `UpdateEffect()` 中 `EffectPaintPropertyNode` 的 `blend_mode` 属性。
* **CSS 和 Clip:**
    * **例子:** 当 CSS 中设置了 `clip-path: circle(50%);`，`UpdateClipPathClip()` 会计算裁剪路径的边界框并更新 `ClipPaintPropertyNode` 的状态，如果裁剪路径过于复杂，则可能标记 `needs_mask_based_clip_path_` 并稍后在 `UpdateEffect()` 中创建基于遮罩的裁剪。
    * **例子:** CSS 的 `clip: rect(10px, 50px, 100px, 20px);` 属性会触发 `UpdateCssClip()` 更新 `ClipPaintPropertyNode`。
    * **例子:**  `overflow: hidden;` 会导致 `UpdateLocalBorderBoxContext()` 和可能的 `UpdateOverflowClip()` 更新 `ClipPaintPropertyNode` 来裁剪溢出内容。
    * **例子:** `border-radius: 10px;` 可能会导致 `UpdateLocalBorderBoxContext()` 和 `UpdateInnerBorderRadiusClip()` 创建 `ClipPaintPropertyNode` 来裁剪边框的圆角。
* **JavaScript:**
    * **例子:**  JavaScript 通过 `element.style.opacity = '0.8';` 修改元素的透明度，会导致重新布局和重绘，最终触发 `UpdateEffect()` 更新绘制属性树。
    * **例子:**  使用 JavaScript 动画库改变元素的 `transform` 或 `filter` 属性，也会导致相应的更新函数被调用。
* **HTML:**
    * **例子:**  `<iframe>` 元素会触发 `UpdateViewTransitionSubframeRootEffect()` 来处理视图过渡的子框架根效果。
    * **例子:**  `<svg>` 元素及其内部的元素在处理滤镜和裁剪时会有特殊的逻辑，例如 `IsClipPathDescendant()` 函数会判断元素是否是 `<clipPath>` 的后代。

**逻辑推理 (假设输入与输出):**

假设一个 `<div>` 元素具有以下 CSS 样式：

```css
.box {
  width: 100px;
  height: 100px;
  opacity: 0.7;
  filter: blur(2px);
  clip-path: circle(50%);
  overflow: hidden;
}
```

**假设输入:**  处理这个 `<div>` 元素的渲染片段。

**逻辑推理过程:**

1. **`NeedsPaintPropertyUpdate()` 返回 `true`:** 因为元素的样式发生了变化，需要更新绘制属性。
2. **`UpdateEffect()`:**
    * `NeedsEffect()` 返回 `true`，因为设置了 `opacity` 和 `filter`。
    * 读取 `opacity: 0.7` 并更新 `EffectPaintPropertyNode` 的 `opacity` 属性。
    * 读取 `filter: blur(2px)` 并更新 `EffectPaintPropertyNode` 的 `filter` 属性。
    * 因为没有 `mask-clip`，所以 `OnClearClip(properties_->ClearMaskClip())` 会被调用。
    * 根据 `opacity` 和 `filter` 的值，设置 `EffectPaintPropertyNode::State` 的其他属性，例如 `blend_mode` 默认为 `kCompositeSourceOver`。
    * 调用 `properties_->UpdateEffect()` 创建或更新 `EffectPaintPropertyNode`。
3. **`UpdateClipPathClip()`:**
    * `NeedsClipPathClipOrMask(object_)` 返回 `true`，因为设置了 `clip-path`。
    * 计算圆形裁剪路径的边界框 `clip_path_bounding_box_`。
    * 将裁剪路径转换为 `Path` 对象。
    * 创建 `ClipPaintPropertyNode::State`，包含裁剪路径和边界框。
    * 调用 `properties_->UpdateClipPathClip()` 创建或更新 `ClipPaintPropertyNode`。
4. **`UpdateCssClip()`:**
    * `NeedsCssClip(object_)` 返回 `false`，因为没有直接设置 `clip` 属性。
    * `OnClearClip(properties_->ClearCssClip())` 会被调用。
5. **`UpdateLocalBorderBoxContext()`:**
    * 由于元素有 `opacity`, `filter`, 和 `clip-path` 相关的绘制属性节点，会设置 `fragment_data_.SetLocalBorderBoxProperties()`，记录当前的 Transform, Clip 和 Effect 节点。

**假设输出:**  更新后的绘制属性树包含了 `EffectPaintPropertyNode` (包含 opacity 和 filter 信息) 和 `ClipPaintPropertyNode` (包含圆形裁剪路径信息)。 `fragment_data_` 记录了这些节点。

**用户或编程常见的使用错误及举例说明:**

* **CSS 语法错误:** 如果 CSS 中 `opacity: 0,8;` (使用了逗号而不是点)，解析会失败，可能导致绘制属性更新不正确或回退到默认值。
* **不理解属性之间的影响:** 用户可能不明白 `opacity: 0` 会阻止元素及其子元素的绘制，即使子元素设置了其他可见的样式。
* **过度使用 `will-change`:**  开发者可能错误地为不需要合成的元素添加 `will-change: transform` 或 `will-change: filter`，导致不必要的 compositor 层创建，增加内存消耗。
* **复杂的 `clip-path` 导致性能问题:**  使用过于复杂或频繁动画的 `clip-path` 可能会导致渲染性能下降，因为需要不断计算和更新裁剪区域。
* **错误地假设 `filter` 会影响布局:** `filter` 主要影响绘制，不会改变元素的布局尺寸。开发者可能会错误地认为添加 `filter` 会撑大元素。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户加载网页:** 浏览器开始解析 HTML 和 CSS。
2. **样式计算:**  浏览器计算出每个元素的最终样式，包括继承和层叠。
3. **布局 (Layout):**  根据样式计算的结果，浏览器计算出每个元素在页面上的位置和大小。
4. **绘制属性树构建 (Paint Property Tree Building):**
    * 遍历渲染树的每个渲染对象。
    * 对于每个渲染对象的每个渲染片段，调用 `FragmentPaintPropertyTreeBuilder::Update()` 或相关的函数。
    * 在 `Update()` 内部，会调用诸如 `UpdateEffect()`, `UpdateClipPathClip()`, `UpdateLocalBorderBoxContext()` 等函数，根据元素的样式和上下文更新绘制属性节点。

**调试线索:**

* **检查元素的 CSS 样式:**  使用浏览器的开发者工具 (Elements 面板) 查看元素的 Computed 样式，确认样式是否如预期。
* **查看渲染层 (Layers):**  在开发者工具的 Layers 面板中，可以查看元素是否被提升为合成层，以及相关的合成原因。这有助于理解为什么某些绘制属性会生效。
* **断点调试:**  在 `blink/renderer/core/paint/paint_property_tree_builder.cc` 中设置断点，跟踪代码执行流程，查看哪些绘制属性被更新，以及更新的值是什么。
* **使用性能分析工具:**  浏览器的 Performance 面板可以记录渲染过程中的各种事件，包括绘制属性树的更新，可以帮助找出性能瓶颈。
* **搜索 Compositing Reasons:** 代码中大量使用了 `CompositingReason` 枚举，可以通过搜索相关的 compositing reason，了解为什么元素会被合成，以及哪些 CSS 属性导致了合成。

**这是第3部分，共6部分，请归纳一下它的功能:**

作为构建绘制属性树过程的第三部分，这段代码专门负责处理 **单个渲染对象片段 (Fragment)** 的绘制属性更新。它接收来自前序阶段的布局信息和样式计算结果，并为该片段构建或更新其在绘制属性树中的 Effect、Clip 等节点信息。这些节点将会在后续的绘制和合成阶段被使用。简单来说，**这一部分负责将渲染对象的视觉样式属性转化为绘制属性树中可供渲染引擎理解和操作的数据结构。**

Prompt: 
```
这是目录为blink/renderer/core/paint/paint_property_tree_builder.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共6部分，请归纳一下它的功能

"""
ined by this object may escape clips.
  if (layer->HasNonContainedAbsolutePositionDescendant()) {
    const auto* container = full_context_.container_for_absolute_position;
    // Check HasLocalBorderBoxProperties() because |container| may not have
    // updated paint properties if it appears in a later box fragment than
    // |object|. TODO(crbug.com/1371426): fix tree walk order in the case.
    if (!container->FirstFragment().HasLocalBorderBoxProperties() ||
        &container->FirstFragment().ContentsClip() != context_.current.clip) {
      return false;
    }
  }
  if (layer->HasFixedPositionDescendant() &&
      !object_.CanContainFixedPositionObjects()) {
    const auto* container = full_context_.container_for_fixed_position;
    // Same as the absolute-position case.
    if (!container->FirstFragment().HasLocalBorderBoxProperties() ||
        &container->FirstFragment().ContentsClip() != context_.current.clip) {
      return false;
    }
  }

  return true;
}

void FragmentPaintPropertyTreeBuilder::UpdateEffect() {
  DCHECK(properties_);
  // Since we're doing a full update, clear list of objects waiting for a
  // deferred update
  object_.GetFrameView()->RemovePendingOpacityUpdate(object_);
  const ComputedStyle& style = object_.StyleRef();

  if (NeedsPaintPropertyUpdate()) {
    if (NeedsEffect()) {
      std::optional<gfx::RectF> mask_clip = CSSMaskPainter::MaskBoundingBox(
          object_, context_.current.paint_offset);
      if (mask_clip || needs_mask_based_clip_path_) {
        DCHECK(mask_clip || clip_path_bounding_box_.has_value());
        gfx::RectF combined_clip =
            mask_clip ? *mask_clip : *clip_path_bounding_box_;
        if (mask_clip && needs_mask_based_clip_path_)
          combined_clip.Intersect(*clip_path_bounding_box_);
        OnUpdateClip(properties_->UpdateMaskClip(
            *context_.current.clip,
            ClipPaintPropertyNode::State(
                *context_.current.transform, combined_clip,
                FloatRoundedRect(gfx::ToEnclosingRect(combined_clip)))));
        // We don't use MaskClip as the output clip of Effect, Mask and
        // ClipPathMask because we only want to apply MaskClip to the contents,
        // not the masks.
      } else {
        OnClearClip(properties_->ClearMaskClip());
      }

      CompositorElementId mask_compositor_element_id;
      if (mask_clip) {
        mask_compositor_element_id =
            GetCompositorElementId(CompositorElementIdNamespace::kEffectMask);
      }

      EffectPaintPropertyNode::State state;
      state.local_transform_space = context_.current.transform;
      if (EffectCanUseCurrentClipAsOutputClip())
        state.output_clip = context_.current.clip;
      state.opacity = style.Opacity();
      if (object_.IsBlendingAllowed()) {
        state.blend_mode = WebCoreCompositeToSkiaComposite(
            kCompositeSourceOver, style.GetBlendMode());
      }
      if (object_.IsBoxModelObject()) {
        if (auto* layer = To<LayoutBoxModelObject>(object_).Layer()) {
          CompositorFilterOperations operations;
          gfx::RRectF bounds;
          layer->UpdateCompositorFilterOperationsForBackdropFilter(operations,
                                                                   bounds);
          if (!operations.IsEmpty()) {
            state.backdrop_filter_info = base::WrapUnique(
                new EffectPaintPropertyNode::BackdropFilterInfo{
                    std::move(operations), bounds, mask_compositor_element_id});
          }
        }
      }

      state.direct_compositing_reasons =
          full_context_.direct_compositing_reasons &
          CompositingReason::kDirectReasonsForEffectProperty;

      // If an effect node exists, add an additional direct compositing reason
      // for 3d transforms and will-change:transform to ensure it is composited.
      state.direct_compositing_reasons |=
          (full_context_.direct_compositing_reasons &
           CompositingReason::kAdditionalEffectCompositingTrigger);

      // We may begin to composite our subtree prior to an animation starts, but
      // a compositor element ID is only needed when an animation is current.
      // Currently, we use the existence of this id to check if effect nodes
      // have been created for animations on this element.
      if (state.direct_compositing_reasons) {
        state.compositor_element_id = GetCompositorElementId(
            CompositorElementIdNamespace::kPrimaryEffect);
      } else {
        // The effect node CompositorElementId is used to uniquely identify
        // renderpasses so even if we don't need one for animations we still
        // need to set an id. Using kPrimary avoids confusing cc::Animation
        // into thinking the element has been composited for animations.
        state.compositor_element_id =
            GetCompositorElementId(CompositorElementIdNamespace::kPrimary);
      }

      state.self_or_ancestor_participates_in_view_transition =
          context_.self_or_ancestor_participates_in_view_transition;

      EffectPaintPropertyNode::AnimationState animation_state;
      animation_state.is_running_opacity_animation_on_compositor =
          style.IsRunningOpacityAnimationOnCompositor();
      animation_state.is_running_backdrop_filter_animation_on_compositor =
          style.IsRunningBackdropFilterAnimationOnCompositor();

      const auto* parent_effect = context_.current_effect;
      // The transition pseudo element doesn't draw into the LayoutView's
      // effect, but rather as its sibling. So this re-parents the effect to
      // whatever the grand-parent effect was. Note that it doesn't matter
      // whether the grand-parent is the root stacking context or something
      // intermediate, as long as it is a sibling of the LayoutView context.
      // This makes it possible to capture the output of the LayoutView context
      // into one of the transition contexts. We also want that capture to be
      // without any additional effects, such as overscroll elasticity effects.
      if (object_.GetNode() &&
          object_.GetNode()->GetPseudoId() == kPseudoIdViewTransition) {
        if (IsInLocalSubframe(object_)) {
          parent_effect = object_.GetDocument()
                              .GetLayoutView()
                              ->FirstFragment()
                              .PaintProperties()
                              ->ViewTransitionSubframeRootEffect();
        } else {
          parent_effect = &EffectPaintPropertyNode::Root();
        }
        DCHECK(parent_effect);
      }
      DCHECK(parent_effect);

      auto effective_change_type = properties_->UpdateEffect(
          *parent_effect, std::move(state), animation_state);
      // If we have simple value change, which means opacity, we should try to
      // directly update it on the PaintArtifactCompositor in order to avoid
      // doing a full rebuild.
      DirectlyUpdateCcOpacity(object_, *properties_, effective_change_type);
      OnUpdateEffect(effective_change_type);

      auto mask_direct_compositing_reasons =
          full_context_.direct_compositing_reasons &
                  CompositingReason::kDirectReasonsForBackdropFilter
              ? CompositingReason::kBackdropFilterMask
              : CompositingReason::kNone;

      if (mask_clip) {
        EffectPaintPropertyNode::State mask_state;
        mask_state.local_transform_space = context_.current.transform;
        mask_state.output_clip = context_.current.clip;
        mask_state.blend_mode = SkBlendMode::kDstIn;
        mask_state.compositor_element_id = mask_compositor_element_id;
        mask_state.direct_compositing_reasons = mask_direct_compositing_reasons;

        if (const auto* old_mask = properties_->Mask()) {
          // The mask node's output clip is used in the property tree state
          // when painting the mask, so the impact of its change should be the
          // same as a clip change in LocalBorderBoxProperties (see
          // UpdateLocalBorderBoxContext()).
          if (old_mask->OutputClip() != mask_state.output_clip)
            OnUpdateClip(PaintPropertyChangeType::kNodeAddedOrRemoved);
        }

        OnUpdateEffect(properties_->UpdateMask(*properties_->Effect(),
                                               std::move(mask_state)));
      } else {
        OnClearEffect(properties_->ClearMask());
      }

      if (needs_mask_based_clip_path_) {
        EffectPaintPropertyNode::State clip_path_state;
        clip_path_state.local_transform_space = context_.current.transform;
        clip_path_state.output_clip = context_.current.clip;
        clip_path_state.blend_mode = SkBlendMode::kDstIn;
        clip_path_state.compositor_element_id = GetCompositorElementId(
            CompositorElementIdNamespace::kEffectClipPath);
        if (!mask_clip) {
          clip_path_state.direct_compositing_reasons =
              mask_direct_compositing_reasons;
        }
        OnUpdateEffect(properties_->UpdateClipPathMask(
            properties_->Mask() ? *properties_->Mask() : *properties_->Effect(),
            std::move(clip_path_state)));
      } else {
        OnClearEffect(properties_->ClearClipPathMask());
      }
    } else {
      OnClearEffect(properties_->ClearEffect());
      OnClearEffect(properties_->ClearMask());
      OnClearEffect(properties_->ClearClipPathMask());
      OnClearClip(properties_->ClearMaskClip());
    }
  }

  if (const auto* effect = properties_->Effect()) {
    context_.current_effect = effect;
    context_.this_or_ancestor_opacity_is_zero |= effect->Opacity() == 0;
    if (properties_->MaskClip()) {
      context_.current.clip = context_.absolute_position.clip =
          context_.fixed_position.clip = properties_->MaskClip();
    }
  }
}

void FragmentPaintPropertyTreeBuilder::UpdateElementCaptureEffect() {
  if (!NeedsPaintPropertyUpdate()) {
    return;
  }

  if (!(full_context_.direct_compositing_reasons &
        CompositingReason::kElementCapture)) {
    OnClearEffect(properties_->ClearElementCaptureEffect());
    return;
  }

  // If we have the correct compositing reason, we should be associated with a
  // node. In the case we are not, the effect is no longer valid.
  auto* element = DynamicTo<Element>(object_.GetNode());
  CHECK(element);
  CHECK(element->GetRestrictionTargetId());
  CHECK(context_.current.clip);
  CHECK(context_.current.transform);
  EffectPaintPropertyNode::State state;
  state.direct_compositing_reasons = CompositingReason::kElementCapture;
  state.local_transform_space = context_.current.transform;
  state.output_clip = context_.current.clip;
  state.restriction_target_id = *element->GetRestrictionTargetId();
  state.compositor_element_id = CompositorElementIdFromUniqueObjectId(
      object_.UniqueId(), CompositorElementIdNamespace::kElementCapture);

  OnUpdateEffect(properties_->UpdateElementCaptureEffect(
      *context_.current_effect, std::move(state), {}));
  context_.current_effect = properties_->ElementCaptureEffect();
}

void FragmentPaintPropertyTreeBuilder::
    UpdateViewTransitionSubframeRootEffect() {
  if (NeedsPaintPropertyUpdate()) {
    const bool needs_node =
        object_.IsLayoutView() && IsInLocalSubframe(object_) &&
        ViewTransitionUtils::GetTransition(object_.GetDocument());

    bool needs_full_invalidation = false;

    if (needs_node) {
      EffectPaintPropertyNode::State state;
      state.local_transform_space = context_.current.transform;
      state.output_clip = context_.current.clip;
      state.compositor_element_id = CompositorElementIdFromUniqueObjectId(
          object_.UniqueId(),
          CompositorElementIdNamespace::kViewTransitionSubframeRoot);
      if (const auto& layer =
              ViewTransitionUtils::GetTransition(object_.GetDocument())
                  ->GetSubframeSnapshotLayer()) {
        state.view_transition_element_resource_id =
            layer->ViewTransitionResourceId();
      }

      auto change_type = properties_->UpdateViewTransitionSubframeRootEffect(
          *context_.current_effect, std::move(state), {});
      needs_full_invalidation =
          change_type >= PaintPropertyChangeType::kNodeAddedOrRemoved;
      OnUpdateEffect(change_type);
    } else {
      bool node_removed = properties_->ClearViewTransitionSubframeRootEffect();
      needs_full_invalidation = node_removed;
      OnClearEffect(node_removed);
    }

    // This node is used an ancestor by nodes generated by descendants of the
    // LayoutView. This means creation or removal of this node needs to be
    // propagated past the isolation for subframes.
    if (needs_full_invalidation) {
      full_context_.force_subtree_update_reasons |=
          PaintPropertyTreeBuilderContext::kSubtreeUpdateIsolationPiercing;
    }
  }

  if (auto* effect = properties_->ViewTransitionSubframeRootEffect()) {
    context_.current_effect = effect;
  }
}

void FragmentPaintPropertyTreeBuilder::UpdateViewTransitionEffect() {
  if (NeedsPaintPropertyUpdate()) {
    const bool old_self_or_ancestor_participates_in_view_transition =
        properties_->ViewTransitionEffect() &&
        properties_->ViewTransitionEffect()
            ->SelfOrAncestorParticipatesInViewTransition();

    const bool is_view_transition_element =
        full_context_.direct_compositing_reasons &
        CompositingReason::kViewTransitionElement;

    const bool needs_view_transition_effect =
        is_view_transition_element ||
        (object_.IsLayoutView() && !IsInLocalSubframe(object_) &&
         !object_.GetDocument().IsSVGDocument());

    if (needs_view_transition_effect) {
      auto* transition =
          ViewTransitionUtils::GetTransition(object_.GetDocument());
      DCHECK(!is_view_transition_element || transition);

      EffectPaintPropertyNode::State state;
      state.local_transform_space = context_.current.transform;
      state.output_clip = context_.current.clip;
      state.compositor_element_id = CompositorElementIdFromUniqueObjectId(
          object_.UniqueId(),
          CompositorElementIdNamespace::kViewTransitionElement);
      if (is_view_transition_element) {
        state.direct_compositing_reasons =
            CompositingReason::kViewTransitionElement;
        state.view_transition_element_resource_id =
            transition->GetSnapshotId(object_);
      }

      // The value isn't set on the root, since clipping rules are different for
      // the root view transition element.
      if (object_.IsLayoutView()) {
        // The LayoutView can only have this bit set from an ancestor if it
        // belongs to a subframe.
        CHECK(!context_.self_or_ancestor_participates_in_view_transition ||
              IsInLocalSubframe(object_));
        state.self_or_ancestor_participates_in_view_transition =
            context_.self_or_ancestor_participates_in_view_transition;
      } else {
        state.self_or_ancestor_participates_in_view_transition = true;
      }

      OnUpdateEffect(properties_->UpdateViewTransitionEffect(
          *context_.current_effect, std::move(state), {}));
    } else {
      OnClearEffect(properties_->ClearViewTransitionEffect());
    }

    // Whether self and ancestor participate in a view transition needs to be
    // propagated to the subtree of the element that set the value.
    const auto* new_effect = properties_->ViewTransitionEffect();
    bool new_self_or_ancestor_participates_in_view_transition =
        new_effect && new_effect->SelfOrAncestorParticipatesInViewTransition();

    if (old_self_or_ancestor_participates_in_view_transition !=
        new_self_or_ancestor_participates_in_view_transition) {
      full_context_.force_subtree_update_reasons |=
          PaintPropertyTreeBuilderContext::kSubtreeUpdateIsolationPiercing;
    }
  }

  if (auto* effect = properties_->ViewTransitionEffect()) {
    context_.current_effect = effect;
    context_.self_or_ancestor_participates_in_view_transition |=
        effect->SelfOrAncestorParticipatesInViewTransition();
  }
}

void FragmentPaintPropertyTreeBuilder::UpdateViewTransitionClip() {
  if (NeedsPaintPropertyUpdate()) {
    if (full_context_.direct_compositing_reasons &
        CompositingReason::kViewTransitionElement) {
      auto* transition =
          ViewTransitionUtils::GetTransition(object_.GetDocument());
      DCHECK(transition);

      if (!transition->NeedsViewTransitionClipNode(object_)) {
        return;
      }

      OnUpdateClip(transition->UpdateCaptureClip(object_, context_.current.clip,
                                                 context_.current.transform));
      context_.current.clip = transition->GetCaptureClip(object_);
    }
  }
}

static bool IsLinkHighlighted(const LayoutObject& object) {
  return object.GetFrame()->GetPage()->GetLinkHighlight().IsHighlighting(
      object);
}

static bool IsClipPathDescendant(const LayoutObject& object) {
  // If the object itself is a resource container (root of a resource subtree)
  // it is not considered a clipPath descendant since it is independent of its
  // ancestors.
  if (object.IsSVGResourceContainer()) {
    return false;
  }
  const LayoutObject* parent = object.Parent();
  while (parent) {
    if (parent->IsSVGResourceContainer()) {
      auto* container = To<LayoutSVGResourceContainer>(parent);
      return container->ResourceType() == kClipperResourceType;
    }
    parent = parent->Parent();
  }
  return false;
}

static bool NeedsFilter(const LayoutObject& object,
                        const PaintPropertyTreeBuilderContext& full_context) {
  if (full_context.direct_compositing_reasons &
      CompositingReason::kDirectReasonsForFilterProperty)
    return true;

  if (object.IsBoxModelObject() &&
      To<LayoutBoxModelObject>(object).HasLayer()) {
    if (object.StyleRef().HasFilter() || object.HasReflection()) {
      return true;
    }
  } else if (object.IsSVGChild() && !object.IsText() &&
             SVGResources::GetClient(object)) {
    if (object.StyleRef().HasFilter()) {
      // Filters don't apply to elements that are descendants of a <clipPath>.
      if (!full_context.has_svg_hidden_container_ancestor ||
          !IsClipPathDescendant(object))
        return true;
    }
  }
  return false;
}

static void UpdateFilterEffect(const LayoutObject& object,
                               const EffectPaintPropertyNode* effect_node,
                               CompositorFilterOperations& filter) {
  if (object.HasLayer()) {
    // Try to use the cached filter.
    if (effect_node) {
      filter = effect_node->Filter();
    }
    PaintLayer* layer = To<LayoutBoxModelObject>(object).Layer();
#if DCHECK_IS_ON()
    // We should have already updated the reference box.
    auto reference_box = layer->FilterReferenceBox();
    layer->UpdateFilterReferenceBox();
    DCHECK_EQ(reference_box, layer->FilterReferenceBox());
#endif
    layer->UpdateCompositorFilterOperationsForFilter(filter);
    return;
  }
  if (object.IsSVGChild() && !object.IsText()) {
    SVGElementResourceClient* client = SVGResources::GetClient(object);
    if (!client)
      return;
    if (!object.StyleRef().HasFilter())
      return;
    // Try to use the cached filter.
    if (effect_node)
      filter = effect_node->Filter();
    client->UpdateFilterData(filter);
  }
}

void FragmentPaintPropertyTreeBuilder::UpdateFilter() {
  DCHECK(properties_);
  if (NeedsPaintPropertyUpdate()) {
    if (NeedsFilter(object_, full_context_)) {
      EffectPaintPropertyNode::State state;
      state.local_transform_space = context_.current.transform;

      UpdateFilterEffect(object_, properties_->Filter(), state.filter);

      // The CSS filter spec didn't specify how filters interact with overflow
      // clips. The implementation here mimics the old Blink/WebKit behavior for
      // backward compatibility.
      // Basically the output of the filter will be affected by clips that
      // applies to the current element. The descendants that paints into the
      // input of the filter ignores any clips collected so far. For example:
      // <div style="overflow:scroll">
      //   <div style="filter:blur(1px);">
      //     <div>A</div>
      //     <div style="position:absolute;">B</div>
      //   </div>
      // </div>
      // In this example "A" should be clipped if the filter was not present.
      // With the filter, "A" will be rastered without clipping, but instead
      // the blurred result will be clipped.
      // "B" should be also clipped because a filter always creates a containing
      // block for all descendants.
      state.output_clip = context_.current.clip;

      // We may begin to composite our subtree prior to an animation starts,
      // but a compositor element ID is only needed when an animation is
      // current.
      state.direct_compositing_reasons =
          full_context_.direct_compositing_reasons &
          CompositingReason::kDirectReasonsForFilterProperty;

      // If a filter node exists, add an additional direct compositing reason
      // for 3d transforms and will-change:transform to ensure it is composited.
      state.direct_compositing_reasons |=
          (full_context_.direct_compositing_reasons &
           CompositingReason::kAdditionalEffectCompositingTrigger);

      state.compositor_element_id =
          GetCompositorElementId(CompositorElementIdNamespace::kEffectFilter);

      state.self_or_ancestor_participates_in_view_transition =
          context_.self_or_ancestor_participates_in_view_transition;

      // This must be computed before std::move(state) below.
      bool needs_pixel_moving_filter_clip_expander =
          (state.direct_compositing_reasons &
           (CompositingReason::kWillChangeFilter |
            CompositingReason::kActiveFilterAnimation)) ||
          state.filter.HasFilterThatMovesPixels();

      EffectPaintPropertyNode::AnimationState animation_state;
      animation_state.is_running_filter_animation_on_compositor =
          object_.StyleRef().IsRunningFilterAnimationOnCompositor();
      OnUpdateEffect(properties_->UpdateFilter(
          *context_.current_effect, std::move(state), animation_state));

      if (needs_pixel_moving_filter_clip_expander) {
        OnUpdateClip(properties_->UpdatePixelMovingFilterClipExpander(
            *context_.current.clip,
            ClipPaintPropertyNode::State(*context_.current.transform,
                                         properties_->Filter())));
      } else {
        OnClearClip(properties_->ClearPixelMovingFilterClipExpander());
      }
    } else {
      OnClearEffect(properties_->ClearFilter());
      OnClearClip(properties_->ClearPixelMovingFilterClipExpander());
    }
  }

  if (properties_->Filter()) {
    context_.current_effect = properties_->Filter();
    if (const auto* input_clip = properties_->PixelMovingFilterClipExpander()) {
      context_.current.clip = input_clip;
    }
  } else {
    DCHECK(!properties_->PixelMovingFilterClipExpander());
  }
}

static FloatRoundedRect ToSnappedClipRect(const PhysicalRect& rect) {
  return FloatRoundedRect(ToPixelSnappedRect(rect));
}

static bool NeedsCssClip(const LayoutObject& object) {
  if (object.HasClip()) {
    DCHECK(!object.IsText());
    return true;
  }
  return false;
}

void FragmentPaintPropertyTreeBuilder::UpdateCssClip() {
  DCHECK(properties_);

  if (NeedsPaintPropertyUpdate()) {
    if (NeedsCssClip(object_)) {
      // Create clip node for descendants that are not fixed position.
      // We don't have to setup context.absolutePosition.clip here because this
      // object must be a container for absolute position descendants, and will
      // copy from in-flow context later at updateOutOfFlowContext() step.
      DCHECK(object_.CanContainAbsolutePositionObjects());
      const auto& clip_rect =
          To<LayoutBox>(object_).ClipRect(context_.current.paint_offset);
      OnUpdateClip(properties_->UpdateCssClip(
          *context_.current.clip,
          ClipPaintPropertyNode::State(*context_.current.transform,
                                       gfx::RectF(clip_rect),
                                       ToSnappedClipRect(clip_rect))));
    } else {
      OnClearClip(properties_->ClearCssClip());
    }
  }

  if (properties_->CssClip())
    context_.current.clip = properties_->CssClip();
}

static std::optional<FloatRoundedRect> PathToRRect(const Path& path) {
  const SkPath sk_path = path.GetSkPath();
  if (sk_path.isInverseFillType()) {
    return std::nullopt;
  }
  SkRect rect;
  if (sk_path.isRect(&rect)) {
    return FloatRoundedRect(gfx::SkRectToRectF(rect));
  }
  SkRRect rrect;
  if (sk_path.isRRect(&rrect)) {
    return FloatRoundedRect(rrect);
  }
  if (sk_path.isOval(&rect)) {
    return FloatRoundedRect(SkRRect::MakeOval(rect));
  }
  return std::nullopt;
}

void FragmentPaintPropertyTreeBuilder::UpdateClipPathClip() {
  if (NeedsPaintPropertyUpdate()) {
    DCHECK(!clip_path_bounding_box_.has_value());
    if (NeedsClipPathClipOrMask(object_)) {
      clip_path_bounding_box_ =
          ClipPathClipper::LocalClipPathBoundingBox(object_);
      if (clip_path_bounding_box_) {
        // SVG "children" does not have a paint offset, but for <foreignObject>
        // the paint offset can still be non-zero since it contains the 'x' and
        // 'y' portion of the geometry. (See also comment in
        // `NeedsPaintOffsetTranslation()`.)
        const gfx::Vector2dF paint_offset =
            !object_.IsSVGChild()
                ? gfx::Vector2dF(context_.current.paint_offset)
                : gfx::Vector2dF();
        clip_path_bounding_box_->Offset(paint_offset);
        if (std::optional<Path> path =
                ClipPathClipper::PathBasedClip(object_)) {
          path->Translate(paint_offset);
          std::optional<FloatRoundedRect> rrect;
          // TODO(crbug.com/337191311): The optimization breaks view-transition
          // if the bounding box of clip-path is larger than the contents.
          if (!(full_context_.direct_compositing_reasons &
                (CompositingReason::kViewTransitionElement |
                 CompositingReason::
                     kViewTransitionElementDescendantWithClipPath))) {
            rrect = PathToRRect(*path);
          }
          ClipPaintPropertyNode::State state(
              *context_.current.transform, *clip_path_bounding_box_,
              rrect.value_or(FloatRoundedRect(
                  gfx::ToEnclosingRect(*clip_path_bounding_box_))));
          if (!rrect) {
            state.clip_path = path;
          }
          OnUpdateClip(properties_->UpdateClipPathClip(*context_.current.clip,
                                                       std::move(state)));
        } else {
          // This means that the clip-path is too complex to be represented as a
          // Path. Will create ClipPathMask in UpdateEffect().
          needs_mask_based_clip_path_ = true;
        }
      }
    }

    if (!clip_path_bounding_box_ || needs_mask_based_clip_path_)
      OnClearClip(properties_->ClearClipPathClip());
  }

  if (properties_->ClipPathClip()) {
    context_.current.clip = context_.absolute_position.clip =
        context_.fixed_position.clip = properties_->ClipPathClip();
  }
}

// The clipping behaviour for replaced elements is defined by overflow,
// overflow-clip-margin and paint containment. See resolution at:
// https://github.com/w3c/csswg-drafts/issues/7144#issuecomment-1090933632
static bool ReplacedElementAlwaysClipsToContentBox(
    const LayoutReplaced& replaced) {
  return !replaced.RespectsCSSOverflow();
}

// TODO(wangxianzhu): Combine the logic by overriding LayoutBox::
// ComputeOverflowClipAxes() in LayoutReplaced and subclasses and remove
// this function.
static bool NeedsOverflowClipForReplacedContents(
    const LayoutReplaced& replaced) {
  // <svg> may optionally allow overflow. If an overflow clip is required,
  // always create it without checking whether the actual content overflows.
  if (replaced.IsSVGRoot())
    return To<LayoutSVGRoot>(replaced).ClipsToContentBox();

  // A replaced element with border-radius always clips the content.
  if (replaced.StyleRef().HasBorderRadius())
    return true;

  // ImagePainter (but not painters for LayoutMedia whose IsImage is also true)
  // won't paint outside of the content box.
  if (replaced.IsImage() && !replaced.IsMedia())
    return false;

  // Non-plugin embedded contents are always sized to fit the content box.
  if (replaced.IsLayoutEmbeddedContent() && !replaced.IsEmbeddedObject())
    return false;

  return true;
}

static bool NeedsOverflowClip(const LayoutObject& object) {
  if (const auto* replaced = DynamicTo<LayoutReplaced>(object)) {
    if (ReplacedElementAlwaysClipsToContentBox(*replaced) ||
        replaced->ClipsToContentBox())
      return NeedsOverflowClipForReplacedContents(*replaced);
  }

  if (object.IsSVGViewportContainer() &&
      SVGLayoutSupport::IsOverflowHidden(object))
    return true;

  if (!object.IsBox())
    return false;

  if (!To<LayoutBox>(object).ShouldClipOverflowAlongEitherAxis())
    return false;

  if (IsA<LayoutView>(object) && !object.GetFrame()->ClipsContent())
    return false;

  return true;
}

void FragmentPaintPropertyTreeBuilder::UpdateLocalBorderBoxContext() {
  if (!NeedsPaintPropertyUpdate())
    return;

  const TransformPaintPropertyNodeOrAlias* old_transform = nullptr;
  const ClipPaintPropertyNodeOrAlias* old_clip = nullptr;
  const EffectPaintPropertyNodeOrAlias* old_effect = nullptr;
  if (fragment_data_.HasLocalBorderBoxProperties()) {
    old_transform = &fragment_data_.LocalBorderBoxProperties().Transform();
    old_clip = &fragment_data_.LocalBorderBoxProperties().Clip();
    old_effect = &fragment_data_.LocalBorderBoxProperties().Effect();
  }
  const TransformPaintPropertyNodeOrAlias* new_transform = nullptr;
  const ClipPaintPropertyNodeOrAlias* new_clip = nullptr;
  const EffectPaintPropertyNodeOrAlias* new_effect = nullptr;

  if (object_.HasLayer() || properties_ || IsLinkHighlighted(object_) ||
      object_.CanContainFixedPositionObjects() ||
      object_.CanContainAbsolutePositionObjects()) {
    new_transform = context_.current.transform;
    new_clip = context_.current.clip;
    new_effect = context_.current_effect;
    fragment_data_.SetLocalBorderBoxProperties(
        PropertyTreeStateOrAlias(*new_transform, *new_clip, *new_effect));
  } else {
    fragment_data_.ClearLocalBorderBoxProperties();
  }

  if (old_transform != new_transform) {
    UpdatePropertyChange(properties_changed_.transform_changed,
                         PaintPropertyChangeType::kNodeAddedOrRemoved);
    properties_changed_.transform_change_is_scroll_translation_only = false;
  }
  if (old_clip != new_clip) {
    UpdatePropertyChange(properties_changed_.clip_changed,
                         PaintPropertyChangeType::kNodeAddedOrRemoved);
  }
  if (old_effect != new_effect) {
    UpdatePropertyChange(properties_changed_.effect_changed,
                         PaintPropertyChangeType::kNodeAddedOrRemoved);
  }
}

bool FragmentPaintPropertyTreeBuilder::NeedsOverflowControlsClip() const {
  if (!object_.IsScrollContainer())
    return false;

  const auto& box = To<LayoutBox>(object_);
  const auto* scrollable_area = box.GetScrollableArea();
  gfx::Rect scroll_controls_bounds =
      scrollable_area->ScrollCornerAndResizerRect();
  if (const auto* scrollbar = scrollable_area->HorizontalScrollbar())
    scroll_controls_bounds.Union(scrollbar->FrameRect());
  if (const auto* scrollbar = scrollable_area->VerticalScrollbar())
    scroll_controls_bounds.Union(scrollbar->FrameRect());
  gfx::Rect pixel_snapped_border_box_rect(
      gfx::Point(), scrollable_area->PixelSnappedBorderBoxSize());
  return !pixel_snapped_border_box_rect.Contains(scroll_controls_bounds);
}

static bool NeedsInnerBorderRadiusClip(const LayoutObject& object) {
  // If a replaced element always clips to its content box then the border
  // radius clip is applied by OverflowClip node. So we don't need to create an
  // additional clip node for the border radius.
  // If the replaced element respects `overflow` property and can have visible
  // overflow, we use a separate node for the border-radius. This is consistent
  // with other elements which respect `overflow`.
  if (object.IsLayoutReplaced() &&
      ReplacedElementAlwaysClipsToContentBox(To<LayoutReplaced>(object))) {
    return false;
  }

  // The check for overflowing both axes is due to this spec line:
  //   However, when one of overflow-x or overflow-y computes to clip and the
  //   other computes to visible, the clipping region is not rounded.
  // (https://drafts.csswg.org/css
"""


```