Response:
Let's break down the thought process for analyzing this code and generating the summary.

1. **Understand the Goal:** The primary goal is to understand the functionality of the `PaintArtifactCompositor` class in the Chromium Blink rendering engine. This includes its relationship to web technologies (JavaScript, HTML, CSS), its internal logic, potential errors, and summarizing its overall purpose.

2. **Identify the Core Class:** The central entity is clearly `PaintArtifactCompositor`. The task is to dissect its methods and data members to understand its role.

3. **Initial Scan for Key Methods:**  A quick scan reveals methods like `Update`, `UpdateRepaintedLayers`, `CreateOrReuseSynthesizedClipLayer`, and `UpdateCompositorViewportProperties`. These suggest the class is responsible for managing the composited layer tree based on paint information.

4. **Analyze `Update`:** This method seems crucial. Its arguments (`PaintArtifact`, `ViewportProperties`, etc.) hint at its role in processing paint information and updating the compositor. The code within `Update` involves:
    * **Layerization:** Calling `Layerizer`. This immediately suggests a responsibility for creating and organizing layers.
    * **Property Tree Management:** Interaction with `PropertyTreeManager`. This points to managing the compositor's property trees (transform, clip, effect, scroll).
    * **Viewport Properties:** Handling viewport-related settings.
    * **Synthesized Clips:** Managing `SynthesizedClip` objects.
    * **Layer Updates:** Iterating through `pending_layers_` and calling `UpdateCompositedLayer`.
    * **Layer Tree Modification:**  `root_layer_->SetChildLayerList`.

5. **Analyze `UpdateRepaintedLayers`:**  This method is explicitly for handling repaints, suggesting an optimization or separate path for updating only changed content. The presence of `DCHECK` statements about property tree changes confirms that full updates should handle property changes.

6. **Investigate `SynthesizedClip`:** The methods `CreateOrReuseSynthesizedClipLayer` and the nested `SynthesizedClip` class are important. They handle the creation and management of layers for clipping purposes. The `PaintContentsToDisplayList` method within `SynthesizedClip` indicates how these clipping layers are rendered.

7. **Examine Direct Update Methods:** Methods like `DirectlyUpdateCompositedOpacityValue`, `DirectlyUpdateTransform`, etc., point to optimizations for directly modifying compositor properties without a full update, likely for animations or smooth transitions.

8. **Consider Relationships with Web Technologies:**
    * **HTML:** The concept of layers and compositing directly relates to how the browser renders the DOM tree represented by HTML.
    * **CSS:** CSS properties like `transform`, `opacity`, `clip-path`, `overflow: scroll`, and filters directly influence compositing decisions and the creation of layers.
    * **JavaScript:** JavaScript animations or style manipulations can trigger updates to the compositor through the mechanisms this class manages.

9. **Look for Error Handling and Assumptions:** The `CHECK` and `DCHECK` statements provide insight into assumptions made by the code and potential error conditions. For example, the checks in `UpdateCompositorViewportProperties` about the inner and outer viewports.

10. **Identify Potential User/Programming Errors:** Based on the functionality, incorrect CSS properties (e.g., conflicting transforms), not triggering necessary repaints after JavaScript modifications, or misunderstandings about how compositing works could lead to issues.

11. **Synthesize and Organize:**  Now, start organizing the findings into logical sections.

    * **Core Functionality:** Start with the main purpose: managing the compositor layer tree.
    * **Key Operations:** Detail the major operations like `Update`, `UpdateRepaintedLayers`, and synthesized clip management.
    * **Web Technology Connections:** Explain how it relates to HTML, CSS, and JavaScript, providing concrete examples.
    * **Logic and Reasoning:** Describe how synthesized clips work, how updates are handled, and the role of property trees.
    * **Potential Errors:** List common pitfalls and incorrect usage.
    * **Summary:**  Provide a concise overview of the class's purpose.

12. **Refine and Iterate:** Review the generated summary for clarity, accuracy, and completeness. Ensure the examples are relevant and easy to understand. For instance, initially, I might just say "handles CSS properties," but it's better to be specific with examples like `transform` and `opacity`. Similarly, initially, I might not explicitly mention the optimization aspect of direct updates.

This iterative process of scanning, analyzing specific methods, identifying relationships, considering potential issues, and then organizing and refining the information allows for a comprehensive understanding and accurate summarization of the code's functionality.
这是对 `blink/renderer/platform/graphics/compositing/paint_artifact_compositor.cc` 文件功能的归纳总结，基于你提供的代码片段。

**功能归纳：**

`PaintArtifactCompositor` 类的主要职责是**管理和更新 Chromium Blink 引擎中的合成（composited）图层树**。它将来自渲染管道的 `PaintArtifact` 数据转换为 `cc::Layer` 对象，并维护这些图层之间的父子关系以及相关的属性（如变换、裁剪、特效等）。

以下是其核心功能的详细归纳：

* **基于 `PaintArtifact` 构建合成图层树:**  `Update` 方法接收一个 `PaintArtifact` 对象，该对象包含了渲染对象及其绘制信息。`PaintArtifactCompositor` 使用这些信息来决定哪些内容需要被提升到独立的合成图层，并创建相应的 `cc::Layer` 对象。
* **管理合成图层的属性:** 它负责设置合成图层的各种属性，例如：
    * **变换 (Transform):** 使用 `TransformPaintPropertyNode` 来设置图层的变换矩阵。
    * **裁剪 (Clip):** 使用 `ClipPaintPropertyNode` 来设置图层的裁剪区域，并能创建或重用合成的裁剪图层 (`SynthesizedClip`).
    * **特效 (Effect):** 使用 `EffectPaintPropertyNode` 来处理图层的特效，例如透明度、滤镜等。
    * **滚动 (Scroll):** 处理滚动相关的属性，并与 `ScrollPaintPropertyNode` 关联。
    * **层叠上下文 (Stacking Context):**  通过图层的父子关系隐式地管理层叠上下文。
* **优化合成图层的创建和重用:**  `CreateOrReuseSynthesizedClipLayer` 方法表明该类会缓存和重用合成的裁剪图层，以提高性能。
* **处理视口属性 (Viewport Properties):** `UpdateCompositorViewportProperties` 方法处理与视口滚动、缩放等相关的属性，并将这些属性注册到合成器。
* **处理重绘 (Repaint):** `UpdateRepaintedLayers` 方法优化了只重绘部分内容时的更新过程，避免了完全重建图层树。
* **直接更新合成器属性 (Direct Updates):** 提供了一些方法 (`DirectlyUpdateCompositedOpacityValue`, `DirectlyUpdateTransform` 等) 允许在某些情况下直接更新合成器的属性，而无需完整的 `Update` 流程，这通常用于动画或其他需要高性能更新的场景。
* **处理滚动 (Scrolling):** 负责处理合成滚动，包括注册滚动属性和直接设置滚动偏移。
* **调试信息:**  支持启用图层调试信息，方便开发者理解合成图层的结构和原因。
* **合成裁剪图层 (Synthesized Clip Layers):**  该类会根据需要创建特殊的合成图层来实现复杂的裁剪效果，`SynthesizedClip` 类就是用来管理这些图层的。
* **与 Property Trees 集成:**  它与 Blink 的 Property Trees 系统紧密集成，利用 Property Nodes 来管理和同步渲染对象的属性到合成器。
* **LayerListBuilder:** 使用 `LayerListBuilder` 来高效地构建和管理合成图层的列表。

**与 JavaScript, HTML, CSS 的关系举例：**

* **CSS `transform` 属性:** 当 CSS 中应用了 `transform` 属性时，`PaintArtifactCompositor` 会接收到对应的 `TransformPaintPropertyNode`，并将其转换为 `cc::Layer` 的变换属性，从而在合成线程中实现动画或定位效果。
    * **假设输入:**  一个 HTML 元素应用了 `style="transform: translate(10px, 20px);"`
    * **输出:** `PaintArtifactCompositor` 会创建一个或更新一个 `cc::Layer`，并设置其变换矩阵，使其在合成时平移 10px 和 20px。

* **CSS `opacity` 属性:**  当 CSS 中设置了 `opacity` 属性时，`PaintArtifactCompositor` 会处理 `EffectPaintPropertyNode`，并更新对应 `cc::Layer` 的透明度。
    * **假设输入:** 一个 HTML 元素应用了 `style="opacity: 0.5;"`
    * **输出:** `PaintArtifactCompositor` 会设置对应 `cc::Layer` 的透明度为 0.5。

* **CSS `clip-path` 属性:**  `clip-path` 属性会导致 `PaintArtifactCompositor` 创建或重用 `SynthesizedClip` 图层。
    * **假设输入:**  一个 HTML 元素应用了 `style="clip-path: circle(50%);"`
    * **输出:** `PaintArtifactCompositor` 会创建一个 `SynthesizedClip` 图层，其内容为一个圆形裁剪路径，并将其关联到需要裁剪的图层。

* **JavaScript 动画:** 当 JavaScript 代码修改元素的 CSS `transform` 或 `opacity` 属性来创建动画时，这些修改最终会通过 `PaintArtifact` 传递到 `PaintArtifactCompositor`，触发图层属性的更新，从而在合成线程中平滑地渲染动画。

* **HTML `<iframe>` 元素:**  `<iframe>` 元素通常会创建独立的合成图层，`PaintArtifactCompositor` 负责管理这些外部图层 (`kForeignLayerRemoteFrame`)。

**逻辑推理的假设输入与输出 (以 `SynthesizedClip` 为例):**

假设输入：

* 一个 `ClipPaintPropertyNode` 对象，描述了一个矩形裁剪区域，且没有复杂的裁剪路径。
* 一个 `TransformPaintPropertyNode` 对象，表示一个简单的平移变换。

输出：

* `PaintArtifactCompositor` 可能选择不创建单独的 `SynthesizedClip` 图层，而是直接将裁剪和变换应用到被裁剪的图层上，因为这种简单的裁剪可以通过图层的属性直接实现。
* 如果裁剪区域很复杂（例如使用了 `clip-path`），则会创建一个 `SynthesizedClip` 图层，其 `PaintContentsToDisplayList` 方法会生成绘制命令来绘制该裁剪形状。

**用户或编程常见的使用错误举例：**

* **忘记触发重绘:** 当 JavaScript 修改了影响布局或绘制的 CSS 属性时，如果没有正确地触发重绘 (例如，通过修改元素的样式)，`PaintArtifactCompositor` 就不会收到更新，导致界面显示与预期不符。
* **过度使用 `will-change`:**  虽然 `will-change` 可以提示浏览器创建合成图层，但过度使用可能会导致内存占用过高，反而降低性能。开发者需要谨慎使用。
* **不理解合成的原理:**  开发者可能会误以为所有的 CSS 属性更改都会导致合成图层的更新。实际上，只有影响视觉效果且需要高性能渲染的属性才会触发合成。不理解这一点可能会导致不必要的性能优化尝试。

总而言之，`PaintArtifactCompositor` 是 Blink 渲染引擎中负责将绘制信息转化为最终在屏幕上显示的合成图层的关键组件，它涉及到性能优化、动画渲染以及复杂视觉效果的实现。

### 提示词
```
这是目录为blink/renderer/platform/graphics/compositing/paint_artifact_compositor.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
layer must be hit testable because the compositor may not know
    // whether the hit test is clipped out.
    // See: cc::LayerTreeHostImpl::IsInitialScrollHitTestReliable().
    layer_->SetHitTestable(true);
  }
  CHECK_EQ(layer_->client(), this);

  const auto& path = clip.ClipPath();
  SkRRect new_rrect(clip.PaintClipRect());
  gfx::Rect layer_rect = gfx::ToEnclosingRect(clip.PaintClipRect().Rect());
  bool needs_display = false;

  gfx::Transform new_projection = GeometryMapper::SourceToDestinationProjection(
      clip.LocalTransformSpace(), transform);
  layer_rect = new_projection.MapRect(layer_rect);
  gfx::Vector2dF layer_offset(layer_rect.OffsetFromOrigin());
  gfx::Size layer_bounds = layer_rect.size();
  AdjustMaskLayerGeometry(transform, layer_offset, layer_bounds);
  new_projection.PostTranslate(-layer_offset);

  if (!path && new_projection.IsIdentityOr2dTranslation()) {
    gfx::Vector2dF translation = new_projection.To2dTranslation();
    new_rrect.offset(translation.x(), translation.y());
    needs_display = !rrect_is_local_ || new_rrect != rrect_;
    projection_.MakeIdentity();
    rrect_is_local_ = true;
  } else {
    needs_display = rrect_is_local_ || new_rrect != rrect_ ||
                    new_projection != projection_ ||
                    !clip.ClipPathEquals(path_);
    projection_ = new_projection;
    rrect_is_local_ = false;
  }

  if (needs_display)
    layer_->SetNeedsDisplay();

  layer_->SetOffsetToTransformParent(layer_offset);
  layer_->SetBounds(layer_bounds);
  rrect_ = new_rrect;
  path_ = path;
}

scoped_refptr<cc::DisplayItemList>
SynthesizedClip::PaintContentsToDisplayList() {
  auto cc_list = base::MakeRefCounted<cc::DisplayItemList>();
  cc::PaintFlags flags;
  flags.setAntiAlias(true);
  cc_list->StartPaint();
  if (rrect_is_local_) {
    cc_list->push<cc::DrawRRectOp>(rrect_, flags);
  } else {
    cc_list->push<cc::SaveOp>();
    if (projection_.IsIdentityOr2dTranslation()) {
      gfx::Vector2dF translation = projection_.To2dTranslation();
      cc_list->push<cc::TranslateOp>(translation.x(), translation.y());
    } else {
      cc_list->push<cc::ConcatOp>(gfx::TransformToSkM44(projection_));
    }
    if (path_) {
      cc_list->push<cc::ClipPathOp>(path_->GetSkPath(), SkClipOp::kIntersect,
                                    true);
    }
    cc_list->push<cc::DrawRRectOp>(rrect_, flags);
    cc_list->push<cc::RestoreOp>();
  }
  cc_list->EndPaintOfUnpaired(gfx::Rect(layer_->bounds()));
  cc_list->Finalize();
  return cc_list;
}

SynthesizedClip& PaintArtifactCompositor::CreateOrReuseSynthesizedClipLayer(
    const ClipPaintPropertyNode& clip,
    const TransformPaintPropertyNode& transform,
    bool needs_layer,
    CompositorElementId& mask_isolation_id,
    CompositorElementId& mask_effect_id) {
  auto entry = base::ranges::find_if(
      synthesized_clip_cache_, [&clip](const auto& entry) {
        return entry.key == &clip && !entry.in_use;
      });
  if (entry == synthesized_clip_cache_.end()) {
    synthesized_clip_cache_.push_back(SynthesizedClipEntry{
        &clip, std::make_unique<SynthesizedClip>(), false});
    entry = synthesized_clip_cache_.end() - 1;
  }

  entry->in_use = true;
  SynthesizedClip& synthesized_clip = *entry->synthesized_clip;
  if (needs_layer) {
    synthesized_clip.UpdateLayer(clip, transform);
    synthesized_clip.Layer()->SetLayerTreeHost(root_layer_->layer_tree_host());
    if (layer_debug_info_enabled_ && !synthesized_clip.Layer()->debug_info())
      synthesized_clip.Layer()->SetDebugName("Synthesized Clip");
  }

  if (!should_always_update_on_scroll_) {
    // If there is any scroll translation between `clip.LocalTransformSpace`
    // and `transform`, the synthesized clip's fast rounded border or layer
    // geometry and paint operations depend on the scroll offset and we need to
    // update them on each scroll of the scroller.
    const auto& clip_transform = clip.LocalTransformSpace().Unalias();
    if (&clip_transform != &transform &&
        &clip_transform.NearestScrollTranslationNode() !=
            &transform.NearestScrollTranslationNode()) {
      should_always_update_on_scroll_ = true;
    }
  }

  mask_isolation_id = synthesized_clip.GetMaskIsolationId();
  mask_effect_id = synthesized_clip.GetMaskEffectId();
  return synthesized_clip;
}

void PaintArtifactCompositor::UpdateCompositorViewportProperties(
    const ViewportProperties& properties,
    PropertyTreeManager& property_tree_manager,
    cc::LayerTreeHost* layer_tree_host) {
  // The inner and outer viewports' existence is linked. That is, either they're
  // both null or they both exist.
  CHECK_EQ(static_cast<bool>(properties.outer_scroll_translation),
           static_cast<bool>(properties.inner_scroll_translation));
  CHECK(!properties.outer_clip ||
        static_cast<bool>(properties.inner_scroll_translation));

  cc::ViewportPropertyIds ids;
  if (properties.overscroll_elasticity_transform) {
    ids.overscroll_elasticity_transform =
        property_tree_manager.EnsureCompositorTransformNode(
            *properties.overscroll_elasticity_transform);
  }
  if (properties.page_scale) {
    ids.page_scale_transform =
        property_tree_manager.EnsureCompositorPageScaleTransformNode(
            *properties.page_scale);
  }
  if (properties.inner_scroll_translation) {
    ids.inner_scroll =
        property_tree_manager.EnsureCompositorInnerScrollAndTransformNode(
            *properties.inner_scroll_translation);
    if (properties.outer_clip) {
      ids.outer_clip = property_tree_manager.EnsureCompositorClipNode(
          *properties.outer_clip);
    }
    CHECK(properties.outer_scroll_translation);
    ids.outer_scroll =
        property_tree_manager.EnsureCompositorOuterScrollAndTransformNode(
            *properties.outer_scroll_translation);

    CHECK(NeedsCompositedScrolling(*properties.inner_scroll_translation));
    CHECK(NeedsCompositedScrolling(*properties.outer_scroll_translation));
    painted_scroll_translations_.insert(
        properties.inner_scroll_translation,
        ScrollTranslationInfo{InfiniteIntRect(), true});
    painted_scroll_translations_.insert(
        properties.outer_scroll_translation,
        ScrollTranslationInfo{InfiniteIntRect(), true});
  }

  layer_tree_host->RegisterViewportPropertyIds(ids);
}

void PaintArtifactCompositor::Update(
    const PaintArtifact& artifact,
    const ViewportProperties& viewport_properties,
    const StackScrollTranslationVector& scroll_translation_nodes,
    Vector<std::unique_ptr<cc::ViewTransitionRequest>> transition_requests) {
  // See: |UpdateRepaintedLayers| for repaint updates.
  DCHECK(needs_update_);
  DCHECK(root_layer_);

  TRACE_EVENT0("blink", "PaintArtifactCompositor::Update");

  // The tree will be null after detaching and this update can be ignored.
  // See: WebViewImpl::detachPaintArtifactCompositor().
  cc::LayerTreeHost* host = root_layer_->layer_tree_host();
  if (!host)
    return;

  for (auto& request : transition_requests)
    host->AddViewTransitionRequest(std::move(request));

  host->property_trees()->scroll_tree_mutable().SetScrollCallbacks(
      scroll_callbacks_);
  root_layer_->set_property_tree_sequence_number(
      g_s_property_tree_sequence_number);

  wtf_size_t old_size = pending_layers_.size();
  OldPendingLayerMatcher old_pending_layer_matcher(std::move(pending_layers_));
  CHECK(painted_scroll_translations_.empty());

  // Make compositing decisions, storing the result in |pending_layers_|.
  pending_layers_ = Layerizer(*this, artifact, old_size).Layerize();
  PendingLayer::DecompositeTransforms(pending_layers_);

  LayerListBuilder layer_list_builder;
  PropertyTreeManager property_tree_manager(*this, *host->property_trees(),
                                            *root_layer_, layer_list_builder,
                                            g_s_property_tree_sequence_number);

  UpdateCompositorViewportProperties(viewport_properties, property_tree_manager,
                                     host);

  should_always_update_on_scroll_ = false;
  for (auto& entry : synthesized_clip_cache_)
    entry.in_use = false;

  // Ensure scroll and scroll translation nodes which may be referenced by
  // AnchorPositionScrollTranslation nodes, to reduce chance of inefficient
  // stale_forward_dependencies in cc::TransformTree::AnchorPositionOffset().
  // We want to create a cc::TransformNode only if the scroller is painted.
  // This avoids violating an assumption in CompositorAnimations that an
  // element has property nodes for either all or none of its animating
  // properties (see crbug.com/1385575).
  // However, we want to create a cc::ScrollNode regardless of whether the
  // scroller is painted. This ensures that scroll offset animations aren't
  // affected by becoming unpainted.
  for (auto& node : scroll_translation_nodes) {
    property_tree_manager.EnsureCompositorScrollNode(*node);
  }
  for (auto& [node, info] : painted_scroll_translations_) {
    property_tree_manager.EnsureCompositorScrollAndTransformNode(
        *node, info.scrolling_contents_cull_rect);
  }

  cc::LayerSelection layer_selection;
  for (auto& pending_layer : pending_layers_) {
    pending_layer.UpdateCompositedLayer(
        old_pending_layer_matcher.Find(pending_layer), layer_selection,
        tracks_raster_invalidations_, root_layer_->layer_tree_host());

    cc::Layer& layer = pending_layer.CcLayer();
    const auto& property_state = pending_layer.GetPropertyTreeState();
    const auto& transform = property_state.Transform();
    const auto& clip = property_state.Clip();
    const auto& effect = property_state.Effect();
    int transform_id =
        property_tree_manager.EnsureCompositorTransformNode(transform);
    int effect_id = property_tree_manager.SwitchToEffectNodeWithSynthesizedClip(
        effect, clip, layer.draws_content());
    int clip_id = property_tree_manager.EnsureCompositorClipNode(clip);

    // We need additional bookkeeping for backdrop-filter mask.
    if (effect.RequiresCompositingForBackdropFilterMask() &&
        effect.CcNodeId(g_s_property_tree_sequence_number) == effect_id) {
      CHECK(pending_layer.GetContentLayerClient());
      static_cast<cc::PictureLayer&>(layer).SetIsBackdropFilterMask(true);
      layer.SetElementId(effect.GetCompositorElementId());
      auto& effect_tree = host->property_trees()->effect_tree_mutable();
      auto* cc_node = effect_tree.Node(effect_id);
      effect_tree.Node(cc_node->parent_id)->backdrop_mask_element_id =
          effect.GetCompositorElementId();
    }

    int scroll_id =
        property_tree_manager.EnsureCompositorScrollAndTransformNode(
            ScrollTranslationStateForLayer(pending_layer), InfiniteIntRect());

    layer_list_builder.Add(&layer);

    layer.set_property_tree_sequence_number(
        root_layer_->property_tree_sequence_number());
    layer.SetTransformTreeIndex(transform_id);
    layer.SetScrollTreeIndex(scroll_id);
    layer.SetClipTreeIndex(clip_id);
    layer.SetEffectTreeIndex(effect_id);
    bool backface_hidden = transform.IsBackfaceHidden();
    layer.SetShouldCheckBackfaceVisibility(backface_hidden);

    if (layer.subtree_property_changed())
      root_layer_->SetNeedsCommit();
  }

  root_layer_->layer_tree_host()->RegisterSelection(layer_selection);

  property_tree_manager.Finalize();

  auto new_end = std::remove_if(
      synthesized_clip_cache_.begin(), synthesized_clip_cache_.end(),
      [](const auto& entry) { return !entry.in_use; });
  synthesized_clip_cache_.Shrink(
      static_cast<wtf_size_t>(new_end - synthesized_clip_cache_.begin()));

  // This should be done before
  // property_tree_manager.UpdateConditionalRenderSurfaceReasons() for which to
  // get property tree node ids from the layers.
  host->property_trees()->set_sequence_number(
      g_s_property_tree_sequence_number);

  auto layers = layer_list_builder.Finalize();
  property_tree_manager.UpdateConditionalRenderSurfaceReasons(layers);
  root_layer_->SetChildLayerList(std::move(layers));

  // Mark the property trees as having been rebuilt.
  host->property_trees()->set_needs_rebuild(false);
  host->property_trees()->ResetCachedData();
  previous_update_for_testing_ = PreviousUpdateType::kFull;

  UpdateDebugInfo();
  painted_scroll_translations_.clear();
  needs_update_ = false;

  g_s_property_tree_sequence_number++;

  // For information about |sequence_number|, see:
  // PaintPropertyNode::changed_sequence_number_|;
  for (auto& chunk : artifact.GetPaintChunks()) {
    chunk.properties.ClearChangedToRoot(g_s_property_tree_sequence_number);
    if (chunk.hit_test_data && chunk.hit_test_data->scroll_translation) {
      chunk.hit_test_data->scroll_translation->ClearChangedToRoot(
          g_s_property_tree_sequence_number);
    }
  }

  DVLOG(2) << "PaintArtifactCompositor::Update() done\n"
           << "Composited layers:\n"
           << GetLayersAsJSON(VLOG_IS_ON(3) ? 0xffffffff : 0)
                  ->ToPrettyJSONString()
                  .Utf8();
}

void PaintArtifactCompositor::UpdateRepaintedLayers(
    const PaintArtifact& repainted_artifact) {
  // |Update| should be used for full updates.
  DCHECK(!needs_update_);

#if DCHECK_IS_ON()
  // Any property tree state change should have caused a full update.
  for (const auto& chunk : repainted_artifact.GetPaintChunks()) {
    // If this fires, a property tree value has changed but we are missing a
    // call to |PaintArtifactCompositor::SetNeedsUpdate|.
    DCHECK(!chunk.properties.Unalias().ChangedToRoot(
        PaintPropertyChangeType::kChangedOnlyNonRerasterValues));
  }
#endif

  cc::LayerSelection layer_selection;
  for (auto& pending_layer : pending_layers_) {
    pending_layer.UpdateCompositedLayerForRepaint(repainted_artifact,
                                                  layer_selection);
  }
  root_layer_->layer_tree_host()->RegisterSelection(layer_selection);
  UpdateDebugInfo();

  previous_update_for_testing_ = PreviousUpdateType::kRepaint;
  needs_update_ = false;

  DVLOG(3) << "PaintArtifactCompositor::UpdateRepaintedLayers() done\n"
           << "Composited layers:\n"
           << GetLayersAsJSON(VLOG_IS_ON(3) ? 0xffffffff : 0)
                  ->ToPrettyJSONString()
                  .Utf8();
}

bool PaintArtifactCompositor::CanDirectlyUpdateProperties() const {
  // Don't try to retrieve property trees if we need an update. The full
  // update will update all of the nodes, so a direct update doesn't need to
  // do anything.
  if (needs_update_)
    return false;

  return root_layer_ && root_layer_->layer_tree_host();
}

bool PaintArtifactCompositor::DirectlyUpdateCompositedOpacityValue(
    const EffectPaintPropertyNode& effect) {
  // We can only directly-update compositor values if all content associated
  // with the node is known to be composited.
  DCHECK(effect.HasDirectCompositingReasons());
  if (CanDirectlyUpdateProperties()) {
    return PropertyTreeManager::DirectlyUpdateCompositedOpacityValue(
        *root_layer_->layer_tree_host(), effect);
  }
  return false;
}

bool PaintArtifactCompositor::DirectlyUpdateScrollOffsetTransform(
    const TransformPaintPropertyNode& transform) {
  if (CanDirectlyUpdateProperties()) {
    return PropertyTreeManager::DirectlyUpdateScrollOffsetTransform(
        *root_layer_->layer_tree_host(), transform);
  }
  return false;
}

bool PaintArtifactCompositor::DirectlyUpdateTransform(
    const TransformPaintPropertyNode& transform) {
  // We can only directly-update compositor values if all content associated
  // with the node is known to be composited.
  DCHECK(transform.HasDirectCompositingReasons());
  // We only assume worst-case overlap testing due to animations (see:
  // |PendingLayer::VisualRectForOverlapTesting|) so we can only use the direct
  // transform update (which skips checking for compositing changes) when
  // animations are present.
  DCHECK(transform.HasActiveTransformAnimation());
  if (CanDirectlyUpdateProperties()) {
    return PropertyTreeManager::DirectlyUpdateTransform(
        *root_layer_->layer_tree_host(), transform);
  }
  return false;
}

bool PaintArtifactCompositor::DirectlyUpdatePageScaleTransform(
    const TransformPaintPropertyNode& transform) {
  // We can only directly-update compositor values if all content associated
  // with the node is known to be composited.
  DCHECK(transform.HasDirectCompositingReasons());
  if (CanDirectlyUpdateProperties()) {
    return PropertyTreeManager::DirectlyUpdatePageScaleTransform(
        *root_layer_->layer_tree_host(), transform);
  }
  return false;
}

bool PaintArtifactCompositor::DirectlySetScrollOffset(
    CompositorElementId element_id,
    const gfx::PointF& scroll_offset) {
  if (!root_layer_ || !root_layer_->layer_tree_host())
    return false;
  auto* property_trees = root_layer_->layer_tree_host()->property_trees();
  if (!property_trees->scroll_tree().FindNodeFromElementId(element_id))
    return false;
  PropertyTreeManager::DirectlySetScrollOffset(*root_layer_->layer_tree_host(),
                                               element_id, scroll_offset);
  return true;
}

void PaintArtifactCompositor::DropCompositorScrollDeltaNextCommit(
    CompositorElementId element_id) {
  if (!root_layer_ || !root_layer_->layer_tree_host()) {
    return;
  }
  auto* property_trees = root_layer_->layer_tree_host()->property_trees();
  if (!property_trees->scroll_tree().FindNodeFromElementId(element_id)) {
    return;
  }
  PropertyTreeManager::DropCompositorScrollDeltaNextCommit(
      *root_layer_->layer_tree_host(), element_id);
}

uint32_t PaintArtifactCompositor::GetMainThreadRepaintReasons(
    const ScrollPaintPropertyNode& scroll) const {
  CHECK(root_layer_);
  if (!root_layer_->layer_tree_host()) {
    return 0;
  }
  return PropertyTreeManager::GetMainThreadRepaintReasons(
      *root_layer_->layer_tree_host(), scroll);
}

bool PaintArtifactCompositor::UsesCompositedScrolling(
    const ScrollPaintPropertyNode& scroll) const {
  CHECK(root_layer_);
  if (!root_layer_->layer_tree_host()) {
    return false;
  }
  return PropertyTreeManager::UsesCompositedScrolling(
      *root_layer_->layer_tree_host(), scroll);
}

void PaintArtifactCompositor::SetLayerDebugInfoEnabled(bool enabled) {
  if (enabled == layer_debug_info_enabled_)
    return;

  DCHECK(needs_update_);
  layer_debug_info_enabled_ = enabled;

  if (enabled) {
    root_layer_->SetDebugName("root");
  } else {
    root_layer_->ClearDebugInfo();
    for (auto& layer : root_layer_->children())
      layer->ClearDebugInfo();
  }
}

void PaintArtifactCompositor::UpdateDebugInfo() const {
  if (!layer_debug_info_enabled_)
    return;

  PropertyTreeState previous_layer_state = PropertyTreeState::Root();
  for (const auto& pending_layer : pending_layers_) {
    cc::Layer& layer = pending_layer.CcLayer();
    RasterInvalidationTracking* tracking = nullptr;
    if (auto* client = pending_layer.GetContentLayerClient()) {
      tracking = client->GetRasterInvalidator().GetTracking();
    }
    cc::LayerDebugInfo& debug_info = layer.EnsureDebugInfo();
    debug_info.name = pending_layer.DebugName().Utf8();
    // GetCompositingReasons calls NeedsCompositedScrolling which is only
    // available during full update. In repaint-only update, the original
    // compositing reasons in debug_info will be kept.
    if (needs_update_) {
      auto compositing_reasons =
          GetCompositingReasons(pending_layer, previous_layer_state);
      debug_info.compositing_reasons =
          CompositingReason::Descriptions(compositing_reasons);
      debug_info.compositing_reason_ids =
          CompositingReason::ShortNames(compositing_reasons);
    }
    debug_info.owner_node_id = pending_layer.OwnerNodeId();

    if (RasterInvalidationTracking::IsTracingRasterInvalidations() &&
        tracking) {
      tracking->AddToLayerDebugInfo(debug_info);
      tracking->ClearInvalidations();
    }
    previous_layer_state = pending_layer.GetPropertyTreeState();
  }
}

// The returned compositing reasons are informative for tracing/debugging.
// Some are based on heuristics so are not fully accurate.
CompositingReasons PaintArtifactCompositor::GetCompositingReasons(
    const PendingLayer& layer,
    const PropertyTreeState& previous_layer_state) const {
  DCHECK(layer_debug_info_enabled_);
  DCHECK(needs_update_);

  if (layer.GetCompositingType() == PendingLayer::kScrollHitTestLayer) {
    return CompositingReason::kOverflowScrolling;
  }
  if (layer.Chunks().size() == 1 && layer.FirstPaintChunk().size() == 1) {
    switch (layer.FirstDisplayItem().GetType()) {
      case DisplayItem::kFixedAttachmentBackground:
        return CompositingReason::kFixedAttachmentBackground;
      case DisplayItem::kCaret:
        return CompositingReason::kCaret;
      case DisplayItem::kScrollbarHorizontal:
      case DisplayItem::kScrollbarVertical:
        return CompositingReason::kScrollbar;
      case DisplayItem::kForeignLayerCanvas:
        return CompositingReason::kCanvas;
      case DisplayItem::kForeignLayerDevToolsOverlay:
        return CompositingReason::kDevToolsOverlay;
      case DisplayItem::kForeignLayerPlugin:
        return CompositingReason::kPlugin;
      case DisplayItem::kForeignLayerVideo:
        return CompositingReason::kVideo;
      case DisplayItem::kForeignLayerRemoteFrame:
        return CompositingReason::kIFrame;
      case DisplayItem::kForeignLayerLinkHighlight:
        return CompositingReason::kLinkHighlight;
      case DisplayItem::kForeignLayerViewportScroll:
        return CompositingReason::kViewport;
      case DisplayItem::kForeignLayerViewportScrollbar:
        return CompositingReason::kScrollbar;
      case DisplayItem::kForeignLayerViewTransitionContent:
        return CompositingReason::kViewTransitionContent;
      default:
        // Will determine compositing reasons based on paint properties.
        break;
    }
  }

  CompositingReasons reasons = CompositingReason::kNone;
  const auto& transform = layer.GetPropertyTreeState().Transform();
  if (transform.IsBackfaceHidden() &&
      !previous_layer_state.Transform().IsBackfaceHidden()) {
    reasons = CompositingReason::kBackfaceVisibilityHidden;
  }
  if (layer.GetCompositingType() == PendingLayer::kOverlap) {
    return reasons == CompositingReason::kNone ? CompositingReason::kOverlap
                                               : reasons;
  }

  auto composited_ancestor = [this](const TransformPaintPropertyNode& transform)
      -> const TransformPaintPropertyNode* {
    const auto* ancestor = transform.NearestDirectlyCompositedAncestor();
    const auto& scroll_translation = transform.NearestScrollTranslationNode();
    if (NeedsCompositedScrolling(scroll_translation) &&
        (!ancestor || ancestor->IsAncestorOf(scroll_translation))) {
      return &scroll_translation;
    }
    return ancestor;
  };

  auto transform_compositing_reasons =
      [composited_ancestor](
          const TransformPaintPropertyNode& transform,
          const TransformPaintPropertyNode& previous) -> CompositingReasons {
    CompositingReasons reasons = CompositingReason::kNone;
    const auto* ancestor = composited_ancestor(transform);
    if (ancestor && ancestor != composited_ancestor(previous)) {
      reasons = ancestor->DirectCompositingReasonsForDebugging();
      if (ancestor->ScrollNode()) {
        reasons |= CompositingReason::kOverflowScrolling;
      }
    }
    return reasons;
  };

  auto clip_compositing_reasons =
      [transform_compositing_reasons](
          const ClipPaintPropertyNode& clip,
          const ClipPaintPropertyNode& previous) -> CompositingReasons {
    return transform_compositing_reasons(
        clip.LocalTransformSpace().Unalias(),
        previous.LocalTransformSpace().Unalias());
  };

  reasons |= transform_compositing_reasons(transform,
                                           previous_layer_state.Transform());
  const auto& effect = layer.GetPropertyTreeState().Effect();
  if (&effect != &previous_layer_state.Effect()) {
    reasons |= effect.DirectCompositingReasonsForDebugging();
    if (reasons == CompositingReason::kNone) {
      reasons = transform_compositing_reasons(
          effect.LocalTransformSpace().Unalias(),
          previous_layer_state.Effect().LocalTransformSpace().Unalias());
      if (reasons == CompositingReason::kNone && effect.OutputClip() &&
          previous_layer_state.Effect().OutputClip()) {
        reasons = clip_compositing_reasons(
            effect.OutputClip()->Unalias(),
            previous_layer_state.Effect().OutputClip()->Unalias());
      }
    }
  }
  if (reasons == CompositingReason::kNone) {
    reasons = clip_compositing_reasons(layer.GetPropertyTreeState().Clip(),
                                       previous_layer_state.Clip());
  }

  return reasons;
}

Vector<cc::Layer*> PaintArtifactCompositor::SynthesizedClipLayersForTesting()
    const {
  Vector<cc::Layer*> synthesized_clip_layers;
  for (const auto& entry : synthesized_clip_cache_) {
    synthesized_clip_layers.push_back(entry.synthesized_clip->Layer());
  }
  return synthesized_clip_layers;
}

size_t PaintArtifactCompositor::ApproximateUnsharedMemoryUsage() const {
  size_t result = sizeof(*this) + synthesized_clip_cache_.CapacityInBytes() +
                  pending_layers_.CapacityInBytes();

  for (auto& layer : pending_layers_) {
    if (auto* client = layer.GetContentLayerClient())
      result += client->ApproximateUnsharedMemoryUsage();
    size_t chunks_size = layer.Chunks().ApproximateUnsharedMemoryUsage();
    DCHECK_GE(chunks_size, sizeof(layer.Chunks()));
    result += chunks_size - sizeof(layer.Chunks());
  }

  return result;
}

bool PaintArtifactCompositor::SetScrollbarNeedsDisplay(
    CompositorElementId element_id) {
  DCHECK(root_layer_);
  CHECK(ScrollbarDisplayItem::IsScrollbarElementId(element_id));
  if (cc::LayerTreeHost* host = root_layer_->layer_tree_host()) {
    if (cc::Layer* layer = host->LayerByElementId(element_id)) {
      layer->SetNeedsDisplay();
      return true;
    }
  }
  // The scrollbar isn't currently composited.
  return false;
}

bool PaintArtifactCompositor::SetScrollbarSolidColor(
    CompositorElementId element_id,
    SkColor4f color) {
  DCHECK(root_layer_);
  CHECK(ScrollbarDisplayItem::IsScrollbarElementId(element_id));
  if (cc::LayerTreeHost* host = root_layer_->layer_tree_host()) {
    if (cc::Layer* layer = host->LayerByElementId(element_id)) {
      if (static_cast<cc::ScrollbarLayerBase*>(layer)
              ->GetScrollbarLayerType() ==
          cc::ScrollbarLayerBase::kSolidColor) {
        static_cast<cc::SolidColorScrollbarLayer*>(layer)->SetColor(color);
        return true;
      }
    }
  }
  // The scrollbar isn't currently composited.
  return false;
}

void LayerListBuilder::Add(scoped_refptr<cc::Layer> layer) {
  DCHECK(list_valid_);
  // Duplicated layers may happen when a foreign layer is fragmented.
  // TODO(wangxianzhu): Change this to DCHECK when we ensure all foreign layers
  // are monolithic (i.e. LayoutNGBlockFragmentation is fully launched).
  if (layer_ids_.insert(layer->id()).is_new_entry)
    list_.push_back(layer);
}

cc::LayerList LayerListBuilder::Finalize() {
  DCHECK(list_valid_);
  list_valid_ = false;
  return std::move(list_);
}

#if DCHECK_IS_ON()
void PaintArtifactCompositor::ShowDebugData() {
  LOG(INFO) << GetLayersAsJSON(kLayerTreeIncludesDebugInfo |
                               kLayerTreeIncludesDetailedInvalidations)
                   ->ToPrettyJSONString()
                   .Utf8();
}
#endif

void PaintArtifactCompositor::ForAllContentLayersForTesting(
    base::FunctionRef<void(ContentLayerClientImpl*)> func) const {
  for (auto& pending_layer : pending_layers_) {
    if (auto* client = pending_layer.GetContentLayerClient()) {
      func(client);
    }
  }
}

ContentLayerClientImpl* PaintArtifactCompositor::ContentLayerClientForTesting(
    wtf_size_t i) const {
  for (auto& pending_layer : pending_layers_) {
    if (auto* client = pending_layer.GetContentLayerClient()) {
      if (i == 0)
        return client;
      --i;
    }
  }
  return nullptr;
}

}  // namespace blink
```