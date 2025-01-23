Response:
The user wants to understand the functionality of the `PropertyTreeManager` class in the Chromium Blink rendering engine, based on the provided C++ source code snippet. I need to analyze the code and explain its purpose, focusing on its interactions with JavaScript, HTML, and CSS, providing examples, logical inferences with inputs and outputs, and common usage errors. Since this is the second part of the explanation, I also need to summarize the overall functionality.

Here's a breakdown of how to approach this:

1. **Identify the core function:** The code heavily revolves around managing property trees, specifically for compositing. It seems to be responsible for translating Blink's paint property nodes (Clip, Effect, Transform) into their compositor counterparts (`cc::ClipNode`, `cc::EffectNode`, `cc::TransformNode`).

2. **Analyze key methods:**
    * `SynthesizeCcEffectsForClipsIfNeeded`: This function seems crucial for creating synthetic compositor effect nodes based on clipping properties. It handles cases where the compositor needs additional effect nodes to correctly apply clips, particularly rounded corners or non-axis-aligned clips.
    * `BuildEffectNodesRecursively`: This function likely traverses the Blink effect property tree and creates corresponding compositor effect nodes.
    * `PopulateCcEffectNode`: This method seems to be responsible for setting the attributes of a compositor effect node based on the Blink effect property node.
    * `UpdateConditionalRenderSurfaceReasons`: This function appears to optimize render surface creation by removing unnecessary surfaces based on layer counts.

3. **Relate to web technologies:**
    * **CSS:** CSS properties like `clip-path`, `border-radius`, `opacity`, `filter`, `backdrop-filter`, `transform`, and blend modes directly influence the creation and configuration of compositor property nodes.
    * **HTML:** The structure of the HTML document influences the hierarchy of paint property nodes.
    * **JavaScript:** While not directly involved in the C++ code, JavaScript can manipulate the DOM and CSS styles, indirectly affecting the property trees. Animations and transitions, often triggered by JavaScript, are also considered.

4. **Infer logic and provide examples:**
    * **Synthetic effects:**  Consider a scenario with a rounded corner. The code creates a synthetic effect node to apply the rounded clip in the compositor. Input: a DOM element with `border-radius`. Output: a `cc::EffectNode` with `mask_filter_info` or a forced render surface.
    * **Axis alignment:** If a clip or transform is not aligned with the render surface, a synthetic effect might be created. Input: a rotated element with a clip. Output: a `cc::EffectNode` with `render_surface_reason` set to `kClipAxisAlignment`.
    * **Backdrop effects:** When `backdrop-filter` is used, the code ensures a render surface is created to define the backdrop scope.

5. **Identify potential errors:**  Focus on common mistakes developers might make that could lead to incorrect compositing. Examples:  Overlapping rounded corners without a render surface, leading to rendering issues.

6. **Synthesize functionality (Part 2):** Combine the observations from the code analysis into a concise summary of the class's role.

7. **Review and refine:** Ensure the explanations are clear, accurate, and provide sufficient detail.

**Self-Correction/Refinement during thought process:**

* Initially, I might focus too much on individual methods. It's important to step back and understand the overall flow of how the `PropertyTreeManager` processes the Blink paint property trees.
* The relationship between synthetic effects and render surfaces needs to be carefully explained. The code shows that synthetic effects are often used to create render surfaces for correct clipping or axis alignment.
* The handling of backdrop effects requires a specific explanation of why and how additional effect nodes and render surfaces are created.
* The optimization of conditional render surfaces is a subtle but important aspect. I need to clearly explain the criteria for omitting these surfaces.
好的，让我们继续分析 `blink/renderer/platform/graphics/compositing/property_tree_manager.cc` 文件的剩余部分，并归纳它的功能。

从提供的代码片段来看，这部分主要关注以下几个方面：

**1. 处理合成的 Compositor Effect 节点 (Synthetic Cc Effects):**

* **`SynthesizeCcEffectsForClipsIfNeeded` 函数:**
    * **功能:**  这个函数的核心职责是根据当前和目标裁剪属性节点 (`current_.clip` 和 `target_clip`) 的差异，以及是否需要处理 backdrop effect，来合成必要的 Compositor Effect 节点。
    * **与 CSS 的关系:** 当 CSS 中使用了 `border-radius` (圆角)、`clip-path` 或者 transform 导致裁剪区域与渲染表面坐标轴不对齐时，就需要合成额外的 Effect 节点来正确实现裁剪。
    * **逻辑推理 (假设输入与输出):**
        * **假设输入:**
            * `current_.clip`: 指向一个矩形裁剪区域的 ClipPaintPropertyNode。
            * `target_clip`: 指向一个带有圆角的裁剪区域的 ClipPaintPropertyNode。
            * `next_effect`: `nullptr`。
        * **输出:**
            * 会创建一个新的合成的 `cc::EffectNode`。
            * 该 `cc::EffectNode` 的 `render_surface_reason` 可能会被设置为 `cc::RenderSurfaceReason::kRoundedCorner`。
            * 如果圆角是通过 shader 实现的，`mask_filter_info` 会被设置。
    * **与 JavaScript/HTML 的关系:** JavaScript 可以动态修改元素的样式，例如添加或修改 `border-radius` 或 `clip-path`，从而触发合成 Effect 节点的过程。
* **`ShaderBasedRRect` 函数:**
    * **功能:** 确定是否可以使用基于 Shader 的方式来实现圆角裁剪，这通常比使用 mask layer 更高效。
    * **与 CSS 的关系:**  直接关联到 `border-radius` 属性。
    * **条件:**  例如，如果圆角的四个角半径相等，且变换是简单的平移，则可能使用 Shader 实现。
* **`ForceRenderSurfaceIfSyntheticRoundedCornerClip` 函数:**
    * **功能:**  如果合成的 Effect 节点是为了处理圆角裁剪，并且当前状态允许，则会强制在该 Effect 节点上创建一个 Render Surface。
    * **原因:**  嵌套的圆角裁剪可能需要 Render Surface 来正确渲染。
* **`PendingClip` 结构体:**  一个辅助结构，用于存储待处理的裁剪信息和类型。

**2. 构建 Compositor Effect 节点 (`BuildEffectNodesRecursively`):**

* **功能:**  这个函数递归地遍历 Blink 的 Effect 属性树，并为每个 Effect 节点创建对应的 `cc::EffectNode`。
* **与 CSS 的关系:** CSS 的 `opacity`, `filter`, `backdrop-filter`, `mix-blend-mode`, `transform` 等属性会影响 `cc::EffectNode` 的配置。
* **处理多组共享 Effect 节点的情况:** 代码中注释提到了在处理 block fragments (如 multicol) 时，可能需要为同一个 Blink Effect 节点创建多个 `cc::EffectNode`。

**3. 配置 Compositor Effect 节点 (`PopulateCcEffectNode`):**

* **功能:**  根据 Blink 的 `EffectPaintPropertyNode` 的信息，填充 `cc::EffectNode` 的各项属性，例如 `opacity`, `filters`, `backdrop_filters`, `blend_mode`, `transform_id`, `clip_id`, `render_surface_reason` 等。
* **与 CSS 的关系:**  该函数直接将 CSS 属性映射到 Compositor 的 Effect 节点属性。
* **与 View Transitions 和 Element Capture 的关系:**  代码中也处理了 View Transitions API (`view_transition_element_resource_id`) 和 Element Capture API (`subtree_capture_id`) 相关的属性。

**4. 优化 Render Surface 的创建 (`UpdateConditionalRenderSurfaceReasons`):**

* **功能:**  该函数遍历 Compositor 的 Layer 列表和 Effect 树，根据 Effect 节点控制的 Layer 和 Render Surface 的数量，来优化条件性 Render Surface 的创建。
* **条件性 Render Surface:**  例如，`opacity` 不为 1 或使用了 blend mode 但只有一个子 Layer 时，可能会创建一个条件性 Render Surface。
* **优化逻辑:** 如果一个条件性 Render Surface 只控制少量 Layer 或子 Render Surface，则可以省略，以提高性能。

**5. 处理 Pixel Moving Filter 的 Clip Expander (`UpdatePixelMovingFilterClipExpanders`):**

* **功能:**  在所有属性节点转换完成后，更新与 Pixel Moving Filter 相关的 Clip 节点的 `pixel_moving_filter_id`。
* **与 CSS 的关系:**  这涉及到一些高级的渲染优化技术，可能与某些特定的 CSS `filter` 效果有关。

**归纳 `PropertyTreeManager` 的功能 (基于提供的两个部分):**

`PropertyTreeManager` 类的核心功能是将 Blink 渲染引擎中的 Paint Property Trees (包括 Transform, Clip 和 Effect) 转换为 Chromium Compositor (CC) 中对应的 Property Trees。它负责：

1. **维护 Compositor Property Trees:**  管理 `cc::TransformTree`, `cc::ClipTree` 和 `cc::EffectTree` 的创建、更新和连接。
2. **转换 Paint Property Nodes 到 Compositor Nodes:**  将 Blink 的 `TransformPaintPropertyNode`, `ClipPaintPropertyNode` 和 `EffectPaintPropertyNode` 转换为 `cc::TransformNode`, `cc::ClipNode` 和 `cc::EffectNode`。
3. **处理合成的 Effect 节点:**  根据需要，例如为了处理圆角、`clip-path` 或非轴对齐的变换，创建额外的合成 `cc::EffectNode`。
4. **优化 Render Surface 的创建:**  根据一定的条件，决定是否需要为特定的 Effect 节点创建 Render Surface，以提高渲染性能。
5. **处理复杂的渲染场景:**  支持 backdrop effects, blend modes, filters, View Transitions 和 Element Capture 等高级渲染特性。
6. **管理 Compositor Element IDs:**  为 Compositor 节点分配和管理稳定的 ID，用于跨进程通信和动画等。
7. **处理 Pixel Moving Filter 的优化。**

**与 JavaScript, HTML, CSS 的关系总结:**

`PropertyTreeManager` 是 Blink 渲染流水线中至关重要的一部分，它将 Web 内容的结构 (HTML) 和样式 (CSS) 信息，以及可能的 JavaScript 动态修改，转化为 Compositor 可以理解和操作的数据结构。

* **CSS 是驱动 `PropertyTreeManager` 行为的主要因素。** 几乎所有的 CSS 视觉属性，如布局、变换、裁剪、透明度、滤镜、混合模式等，都会直接或间接地影响 Property Tree 的构建和配置。
* **HTML 的结构决定了 Paint Property Tree 的层级关系。** 元素的嵌套和渲染顺序会影响 Property Node 之间的父子关系。
* **JavaScript 可以通过 DOM 操作和 CSS 样式修改，动态地改变 Property Trees。** 例如，JavaScript 动画或交互效果可能会改变元素的 `transform`, `opacity` 等属性，从而触发 `PropertyTreeManager` 更新 Compositor Property Trees。

**常见的用户或编程使用错误 (与 `PropertyTreeManager` 的交互层面):**

虽然开发者通常不会直接与 `PropertyTreeManager` 交互，但一些常见的 Web 开发错误会影响到它的工作，导致渲染问题：

* **过度使用 `will-change` 属性:**  不恰当的使用 `will-change` 可能会导致过多的 Render Surface 被创建，反而降低性能。
* **复杂动画和变换:**  过于复杂的 CSS 动画和变换可能导致 Property Tree 更新过于频繁，影响性能。
* **不必要的 Render Surface 创建:**  例如，在不需要的情况下使用会导致 Render Surface 创建的 CSS 属性 (如某些 `filter` 或 `isolation`)。
* **嵌套的复杂效果:**  例如，多层嵌套的带有 `backdrop-filter` 或复杂 `clip-path` 的元素，可能会导致 Compositor Property Tree 变得复杂，影响性能。
* **在不支持硬件加速的场景下使用复杂效果:** 这会导致回退到软件渲染，性能会很差。

总而言之，`PropertyTreeManager` 在 Blink 渲染引擎中扮演着连接 Web 内容描述和 GPU 加速渲染的关键角色。它负责将高级的 Web 概念转化为底层的渲染指令，并尽力优化渲染过程。

### 提示词
```
这是目录为blink/renderer/platform/graphics/compositing/property_tree_manager.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
_C1_1M
  //     +- E_C1_2 <-- E_C1_2M
  // C0 <-- C1
  // [L0(E1,C0), L1(E_C1_1, C1), L1M(E_C1_1M, C1), L2(E_C1_2, C1),
  //  L2M(E_C1_2M, C1)]
  // In effect stack diagram:
  //                 L1M(C1)
  //        L1(C1) [ E_C1_1M ]          L2M(C1)
  // L0(C0) [     E_C1_1     ] L2(C1) [ E_C1_2M ]
  // [          E1           ][     E_C1_2      ]
  // [                    E0                    ]
  //
  // As the caller iterates the layer list, the sequence of events happen in
  // the following order:
  // Prior to emitting P0, this method is invoked with (E1, C0). A compositor
  // effect node for E1 is generated as we are entering it. The caller emits P0.
  // Prior to emitting P1, this method is invoked with (E1, C1). A synthetic
  // compositor effect for C1 is generated as we are entering it. The caller
  // emits P1.
  // Prior to emitting P2, this method is invoked with (E0, C1). Both previously
  // entered effects must be closed, because synthetic effect for C1 is enclosed
  // by E1, thus must be closed before E1 can be closed. A mask layer L1M is
  // generated along with an internal effect node for blending. After closing
  // both effects, C1 has to be entered again, thus generates another synthetic
  // compositor effect. The caller emits P2.
  // At last, the caller invokes Finalize() to close the unclosed synthetic
  // effect. Another mask layer L2M is generated, along with its internal
  // effect node for blending.
  const auto& ancestor =
      current_.effect->LowestCommonAncestor(next_effect).Unalias();
  while (current_.effect != &ancestor)
    CloseCcEffect();

  BuildEffectNodesRecursively(next_effect);
  SynthesizeCcEffectsForClipsIfNeeded(next_clip, /*next_effect*/ nullptr);

  if (layer_draws_content)
    pending_synthetic_mask_layers_.clear();

  return current_.effect_id;
}

static bool IsNodeOnAncestorChain(const ClipPaintPropertyNode& find,
                                  const ClipPaintPropertyNode& current,
                                  const ClipPaintPropertyNode& ancestor) {
  // Precondition: |ancestor| must be an (inclusive) ancestor of |current|
  // otherwise the behavior is undefined.
  // Returns true if node |find| is one of the node on the ancestor chain
  // [current, ancestor). Returns false otherwise.
  DCHECK(ancestor.IsAncestorOf(current));

  for (const auto* node = &current; node != &ancestor;
       node = node->UnaliasedParent()) {
    if (node == &find)
      return true;
  }
  return false;
}

bool PropertyTreeManager::EffectStateMayBe2dAxisMisalignedToRenderSurface(
    EffectState& state,
    wtf_size_t index) {
  if (state.may_be_2d_axis_misaligned_to_render_surface ==
      EffectState::kUnknown) {
    // The root effect has render surface, so it's always kAligned.
    DCHECK_NE(0u, index);
    if (EffectStateMayBe2dAxisMisalignedToRenderSurface(
            effect_stack_[index - 1], index - 1)) {
      state.may_be_2d_axis_misaligned_to_render_surface =
          EffectState::kMisaligned;
    } else {
      state.may_be_2d_axis_misaligned_to_render_surface =
          TransformsMayBe2dAxisMisaligned(*effect_stack_[index - 1].transform,
                                          *current_.transform)
              ? EffectState::kMisaligned
              : EffectState::kAligned;
    }
  }
  return state.may_be_2d_axis_misaligned_to_render_surface ==
         EffectState::kMisaligned;
}

bool PropertyTreeManager::CurrentEffectMayBe2dAxisMisalignedToRenderSurface() {
  // |current_| is virtually the top of effect_stack_.
  return EffectStateMayBe2dAxisMisalignedToRenderSurface(current_,
                                                         effect_stack_.size());
}

PropertyTreeManager::CcEffectType PropertyTreeManager::SyntheticEffectType(
    const ClipPaintPropertyNode& clip) {
  unsigned effect_type = CcEffectType::kEffect;
  if (clip.PaintClipRect().IsRounded() || clip.ClipPath())
    effect_type |= CcEffectType::kSyntheticForNonTrivialClip;

  // Cc requires that a rectangluar clip is 2d-axis-aligned with the render
  // surface to correctly apply the clip.
  if (CurrentEffectMayBe2dAxisMisalignedToRenderSurface() ||
      TransformsMayBe2dAxisMisaligned(clip.LocalTransformSpace().Unalias(),
                                      *current_.transform))
    effect_type |= CcEffectType::kSyntheticFor2dAxisAlignment;
  return static_cast<CcEffectType>(effect_type);
}

void PropertyTreeManager::ForceRenderSurfaceIfSyntheticRoundedCornerClip(
    PropertyTreeManager::EffectState& state) {
  if (state.effect_type & CcEffectType::kSyntheticForNonTrivialClip) {
    auto& effect_node = *effect_tree_.Node(state.effect_id);
    effect_node.render_surface_reason = cc::RenderSurfaceReason::kRoundedCorner;
  }
}

struct PendingClip {
  DISALLOW_NEW();

 public:
  Member<const ClipPaintPropertyNode> clip;
  PropertyTreeManager::CcEffectType type;

  void Trace(Visitor* visitor) const { visitor->Trace(clip); }
};

std::optional<gfx::RRectF> PropertyTreeManager::ShaderBasedRRect(
    const ClipPaintPropertyNode& clip,
    PropertyTreeManager::CcEffectType type,
    const TransformPaintPropertyNode& transform,
    const EffectPaintPropertyNode* next_effect) {
  if (type & CcEffectType::kSyntheticFor2dAxisAlignment) {
    return std::nullopt;
  }
  if (clip.ClipPath()) {
    return std::nullopt;
  }

  auto WidthAndHeightAreTheSame = [](const gfx::SizeF& size) {
    return size.width() == size.height();
  };

  const FloatRoundedRect::Radii& radii = clip.PaintClipRect().GetRadii();
  if (!WidthAndHeightAreTheSame(radii.TopLeft()) ||
      !WidthAndHeightAreTheSame(radii.TopRight()) ||
      !WidthAndHeightAreTheSame(radii.BottomRight()) ||
      !WidthAndHeightAreTheSame(radii.BottomLeft())) {
    return std::nullopt;
  }

  // Rounded corners that differ are not supported by the CALayerOverlay system
  // on Mac. Instead of letting it fall back to the (worse for memory and
  // battery) non-CALayerOverlay system for such cases, fall back to a
  // non-shader border-radius mask for the effect node.
#if BUILDFLAG(IS_MAC)
  if (radii.TopLeft() != radii.TopRight() ||
      radii.TopLeft() != radii.BottomRight() ||
      radii.TopLeft() != radii.BottomLeft()) {
    return std::nullopt;
  }
#endif

  gfx::Vector2dF translation;
  if (&transform != &clip.LocalTransformSpace()) {
    gfx::Transform projection = GeometryMapper::SourceToDestinationProjection(
        clip.LocalTransformSpace(), transform);
    if (!projection.IsIdentityOr2dTranslation()) {
      return std::nullopt;
    }
    translation = projection.To2dTranslation();
  }

  SkRRect rrect(clip.PaintClipRect());
  rrect.offset(translation.x(), translation.y());
  if (!rrect.isValid()) {
    return std::nullopt;
  }
  return gfx::RRectF(rrect);
}

int PropertyTreeManager::SynthesizeCcEffectsForClipsIfNeeded(
    const ClipPaintPropertyNode& target_clip,
    const EffectPaintPropertyNode* next_effect) {
  int backdrop_effect_clip_id = cc::kInvalidPropertyNodeId;
  bool should_realize_backdrop_effect = false;
  if (next_effect && next_effect->MayHaveBackdropEffect()) {
    // Exit all synthetic effect node if the next child has backdrop effect
    // (exotic blending mode or backdrop filter) because it has to access the
    // backdrop of enclosing effect.
    while (IsCurrentCcEffectSynthetic())
      CloseCcEffect();

    // An effect node can't omit render surface if it has child with backdrop
    // effect, in order to define the scope of the backdrop.
    effect_tree_.Node(current_.effect_id)->render_surface_reason =
        cc::RenderSurfaceReason::kBackdropScope;
    should_realize_backdrop_effect = true;
    backdrop_effect_clip_id = EnsureCompositorClipNode(target_clip);
  } else {
    // Exit synthetic effects until there are no more synthesized clips below
    // our lowest common ancestor.
    const auto& lca =
        current_.clip->LowestCommonAncestor(target_clip).Unalias();
    while (current_.clip != &lca) {
      if (!IsCurrentCcEffectSynthetic()) {
        // TODO(crbug.com/803649): We still have clip hierarchy issues with
        // fragment clips. See crbug.com/1238656 for the test case. Will change
        // the above condition to DCHECK after LayoutNGBlockFragmentation is
        // fully launched.
        return cc::kInvalidPropertyNodeId;
      }
      const auto* pre_exit_clip = current_.clip.Get();
      CloseCcEffect();
      // We may run past the lowest common ancestor because it may not have
      // been synthesized.
      if (IsNodeOnAncestorChain(lca, *pre_exit_clip, *current_.clip))
        break;
    }
  }

  HeapVector<PendingClip, 8> pending_clips;
  const ClipPaintPropertyNode* clip_node = &target_clip;
  for (; clip_node && clip_node != current_.clip;
       clip_node = clip_node->UnaliasedParent()) {
    if (auto type = SyntheticEffectType(*clip_node))
      pending_clips.emplace_back(PendingClip{clip_node, type});
  }

  if (!clip_node) {
    // TODO(crbug.com/803649): We still have clip hierarchy issues with
    // fragment clips. See crbug.com/1238656 for the test case. Will change
    // the above condition to DCHECK after LayoutNGBlockFragmentation is fully
    // launched.
    return cc::kInvalidPropertyNodeId;
  }

  if (pending_clips.empty())
    return cc::kInvalidPropertyNodeId;

  int cc_effect_id_for_backdrop_effect = cc::kInvalidPropertyNodeId;
  for (auto i = pending_clips.size(); i--;) {
    auto& pending_clip = pending_clips[i];
    int clip_id = backdrop_effect_clip_id;

    // For a non-trivial clip, the synthetic effect is an isolation to enclose
    // only the layers that should be masked by the synthesized clip.
    // For a non-2d-axis-preserving clip, the synthetic effect creates a render
    // surface which is axis-aligned with the clip.
    cc::EffectNode& synthetic_effect = *effect_tree_.Node(
        effect_tree_.Insert(cc::EffectNode(), current_.effect_id));

    const auto& transform =
        should_realize_backdrop_effect
            ? next_effect->LocalTransformSpace().Unalias()
            : pending_clip.clip->LocalTransformSpace().Unalias();

    if (pending_clip.type & CcEffectType::kSyntheticFor2dAxisAlignment) {
      if (should_realize_backdrop_effect) {
        // We need a synthetic mask clip layer for the non-2d-axis-aligned clip
        // when we also need to realize a backdrop effect.
        pending_clip.type = static_cast<CcEffectType>(
            pending_clip.type | CcEffectType::kSyntheticForNonTrivialClip);
      } else {
        synthetic_effect.element_id =
            CompositorElementIdFromUniqueObjectId(NewUniqueObjectId());
        synthetic_effect.render_surface_reason =
            cc::RenderSurfaceReason::kClipAxisAlignment;
        // The clip of the synthetic effect is the parent of the clip, so that
        // the clip itself will be applied in the render surface.
        DCHECK(pending_clip.clip->UnaliasedParent());
        clip_id =
            EnsureCompositorClipNode(*pending_clip.clip->UnaliasedParent());
      }
    }

    if (pending_clip.type & CcEffectType::kSyntheticForNonTrivialClip) {
      if (clip_id == cc::kInvalidPropertyNodeId) {
        const auto* clip = pending_clip.clip.Get();
        // Some virtual/threaded/external/wpt/css/css-view-transitions/*
        // tests will fail without the following condition.
        // TODO(crbug.com/1345805): Investigate the reason and remove the
        // condition if possible.
        if (!current_.effect->ViewTransitionElementResourceId().IsValid()) {
          // Use the parent clip as the output clip of the synthetic effect so
          // that the clip will apply to the masked contents but not the mask
          // layer, to ensure the masked content is fully covered by the mask
          // layer (after AdjustMaskLayerGeometry) in case of rounding errors
          // of the clip in the compositor.
          DCHECK(clip->UnaliasedParent());
          clip = clip->UnaliasedParent();
        }
        clip_id = EnsureCompositorClipNode(*clip);
      }
      // For non-trivial clip, isolation_effect.element_id will be assigned
      // later when the effect is closed. For now the default value ElementId()
      // is used. See PropertyTreeManager::EmitClipMaskLayer().
      if (std::optional<gfx::RRectF> rrect = ShaderBasedRRect(
              *pending_clip.clip, pending_clip.type, transform, next_effect)) {
        synthetic_effect.mask_filter_info = gfx::MaskFilterInfo(*rrect);
        synthetic_effect.is_fast_rounded_corner = true;

        // Nested rounded corner clips need to force render surfaces for
        // clips other than the leaf ones, because the compositor doesn't
        // know how to apply two rounded clips to the same draw quad.
        if (current_.contained_by_non_render_surface_synthetic_rounded_clip) {
          ForceRenderSurfaceIfSyntheticRoundedCornerClip(current_);
          for (auto effect_it = effect_stack_.rbegin();
               effect_it != effect_stack_.rend(); ++effect_it) {
            auto& effect_node = *effect_tree_.Node(effect_it->effect_id);
            if (effect_node.HasRenderSurface() &&
                !IsConditionalRenderSurfaceReason(
                    effect_node.render_surface_reason)) {
              break;
            }
            ForceRenderSurfaceIfSyntheticRoundedCornerClip(*effect_it);
          }
        }
      } else {
        synthetic_effect.render_surface_reason =
            pending_clip.clip->PaintClipRect().IsRounded()
                ? cc::RenderSurfaceReason::kRoundedCorner
                : cc::RenderSurfaceReason::kClipPath;
      }
      pending_synthetic_mask_layers_.insert(synthetic_effect.id);
    }

    if (should_realize_backdrop_effect) {
      // Move the effect node containing backdrop effects up to the outermost
      // synthetic effect to ensure the backdrop effects can access the correct
      // backdrop.
      DCHECK(next_effect);
      DCHECK_EQ(cc_effect_id_for_backdrop_effect, cc::kInvalidPropertyNodeId);
      PopulateCcEffectNode(synthetic_effect, *next_effect, clip_id);
      cc_effect_id_for_backdrop_effect = synthetic_effect.id;
      should_realize_backdrop_effect = false;
    } else {
      synthetic_effect.clip_id = clip_id;
    }

    synthetic_effect.transform_id = EnsureCompositorTransformNode(transform);
    synthetic_effect.double_sided = !transform.IsBackfaceHidden();

    effect_stack_.emplace_back(current_);
    SetCurrentEffectState(synthetic_effect, pending_clip.type, *current_.effect,
                          *pending_clip.clip, transform);
  }

  return cc_effect_id_for_backdrop_effect;
}

void PropertyTreeManager::BuildEffectNodesRecursively(
    const EffectPaintPropertyNode& next_effect) {
  if (&next_effect == current_.effect)
    return;

  DCHECK(next_effect.UnaliasedParent());
  BuildEffectNodesRecursively(*next_effect.UnaliasedParent());
  DCHECK_EQ(next_effect.UnaliasedParent(), current_.effect);

  bool has_multiple_groups = false;
  if (effect_tree_.Node(next_effect.CcNodeId(new_sequence_number_))) {
    // TODO(crbug.com/1064341): We have to allow one blink effect node to apply
    // to multiple groups in block fragments (multicol, etc.) due to the
    // current FragmentClip implementation. This can only be fixed by LayoutNG
    // block fragments. For now we'll create multiple cc effect nodes in the
    // case.
    // TODO(crbug.com/1253797): Actually this still happens with LayoutNG block
    // fragments due to paint order issue.
    has_multiple_groups = true;
  }

  int real_effect_node_id = cc::kInvalidPropertyNodeId;
  int output_clip_id = 0;
  const ClipPaintPropertyNode* output_clip = nullptr;
  if (next_effect.OutputClip()) {
    output_clip = &next_effect.OutputClip()->Unalias();
    real_effect_node_id =
        SynthesizeCcEffectsForClipsIfNeeded(*output_clip, &next_effect);
    output_clip_id = EnsureCompositorClipNode(*output_clip);
  } else {
    // If we don't have an output clip, then we'll use the clip of the last
    // non-synthetic effect. This means we should close all synthetic effects
    // on the stack first.
    while (IsCurrentCcEffectSynthetic())
      CloseCcEffect();

    output_clip = current_.clip;
    DCHECK(output_clip);
    output_clip_id = effect_tree_.Node(current_.effect_id)->clip_id;
    DCHECK_EQ(output_clip_id, EnsureCompositorClipNode(*output_clip));
  }

  const auto& transform = next_effect.LocalTransformSpace().Unalias();
  auto& effect_node = *effect_tree_.Node(
      effect_tree_.Insert(cc::EffectNode(), current_.effect_id));
  if (real_effect_node_id == cc::kInvalidPropertyNodeId) {
    real_effect_node_id = effect_node.id;

    // |has_multiple_groups| implies that this paint effect node is split into
    // multiple CC effect nodes. This happens when we have non-contiguous paint
    // chunks which share the same paint effect node and as a result the same
    // shared element resource ID.
    // Since a shared element resource ID must be associated with a single CC
    // effect node, the code ensures that only one CC effect node (associated
    // with the first contiguous set of chunks) is tagged with the shared
    // element resource ID. The view transition should either prevent such
    // content or ensure effect nodes are contiguous. See crbug.com/1303081 for
    // details. This restriction also applies to element capture.
    DCHECK((!next_effect.ViewTransitionElementResourceId().IsValid() &&
            next_effect.ElementCaptureId()->is_zero()) ||
           !has_multiple_groups)
        << next_effect.ToString();
    PopulateCcEffectNode(effect_node, next_effect, output_clip_id);
  } else {
    // We have used the outermost synthetic effect for |next_effect| in
    // SynthesizeCcEffectsForClipsIfNeeded(), so |effect_node| is just a dummy
    // node to mark the end of continuous synthetic effects for |next_effect|.
    effect_node.clip_id = output_clip_id;
    effect_node.transform_id = EnsureCompositorTransformNode(transform);
    effect_node.element_id = next_effect.GetCompositorElementId();
  }

  if (has_multiple_groups) {
    if (effect_node.element_id) {
      // We are creating more than one cc effect nodes for one blink effect.
      // Give the extra cc effect node a unique stable id.
      effect_node.element_id =
          CompositorElementIdFromUniqueObjectId(NewUniqueObjectId());
    }
  } else {
    next_effect.SetCcNodeId(new_sequence_number_, real_effect_node_id);
  }

  CompositorElementId compositor_element_id =
      next_effect.GetCompositorElementId();
  if (compositor_element_id && !has_multiple_groups) {
    DCHECK(!effect_tree_.FindNodeFromElementId(compositor_element_id));
    effect_tree_.SetElementIdForNodeId(real_effect_node_id,
                                       compositor_element_id);
  }

  effect_stack_.emplace_back(current_);
  SetCurrentEffectState(effect_node, CcEffectType::kEffect, next_effect,
                        *output_clip, transform);
}

// See IsConditionalRenderSurfaceReason() for the definition of conditional
// render surface.
static cc::RenderSurfaceReason ConditionalRenderSurfaceReasonForEffect(
    const EffectPaintPropertyNode& effect) {
  if (effect.BlendMode() == SkBlendMode::kDstIn)
    return cc::RenderSurfaceReason::kBlendModeDstIn;
  if (effect.Opacity() != 1.f)
    return cc::RenderSurfaceReason::kOpacity;
  // TODO(crbug.com/1285498): Optimize for will-change: opacity.
  if (effect.HasActiveOpacityAnimation())
    return cc::RenderSurfaceReason::kOpacityAnimation;
  return cc::RenderSurfaceReason::kNone;
}

static cc::RenderSurfaceReason RenderSurfaceReasonForEffect(
    const EffectPaintPropertyNode& effect) {
  if (!effect.Filter().IsEmpty() ||
      effect.RequiresCompositingForWillChangeFilter()) {
    return cc::RenderSurfaceReason::kFilter;
  }
  if (effect.HasActiveFilterAnimation())
    return cc::RenderSurfaceReason::kFilterAnimation;
  if (effect.BackdropFilter() ||
      effect.RequiresCompositingForWillChangeBackdropFilter()) {
    return cc::RenderSurfaceReason::kBackdropFilter;
  }
  if (effect.HasActiveBackdropFilterAnimation())
    return cc::RenderSurfaceReason::kBackdropFilterAnimation;
  if (effect.BlendMode() != SkBlendMode::kSrcOver &&
      // The render surface for kDstIn is conditional. See above functions.
      effect.BlendMode() != SkBlendMode::kDstIn) {
    return cc::RenderSurfaceReason::kBlendMode;
  }
  if (effect.ViewTransitionElementResourceId().IsValid()) {
    return cc::RenderSurfaceReason::kViewTransitionParticipant;
  }
  // If the effect's transform node flattens the transform while it
  // participates in the 3d sorting context of an ancestor, cc needs a
  // render surface for correct flattening.
  // TODO(crbug.com/504464): Move the logic into cc compositor thread.
  if (effect.FlattensAtLeafOf3DScene())
    return cc::RenderSurfaceReason::k3dTransformFlattening;

  if (!effect.ElementCaptureId()->is_zero()) {
    return cc::RenderSurfaceReason::kSubtreeIsBeingCaptured;
  }
  auto conditional_reason = ConditionalRenderSurfaceReasonForEffect(effect);
  DCHECK(conditional_reason == cc::RenderSurfaceReason::kNone ||
         IsConditionalRenderSurfaceReason(conditional_reason));
  return conditional_reason;
}

void PropertyTreeManager::PopulateCcEffectNode(
    cc::EffectNode& effect_node,
    const EffectPaintPropertyNode& effect,
    int output_clip_id) {
  effect_node.element_id = effect.GetCompositorElementId();
  effect_node.clip_id = output_clip_id;
  effect_node.render_surface_reason = RenderSurfaceReasonForEffect(effect);
  effect_node.opacity = effect.Opacity();
  const auto& transform = effect.LocalTransformSpace().Unalias();
  effect_node.transform_id = EnsureCompositorTransformNode(transform);
  if (effect.MayHaveBackdropEffect()) {
    // We never have backdrop effect and filter on the same effect node.
    DCHECK(effect.Filter().IsEmpty());
    if (auto* backdrop_filter = effect.BackdropFilter()) {
      effect_node.backdrop_filters = backdrop_filter->AsCcFilterOperations();
      effect_node.backdrop_filter_bounds = effect.BackdropFilterBounds();
      effect_node.backdrop_mask_element_id = effect.BackdropMaskElementId();
    }
    effect_node.blend_mode = effect.BlendMode();
  } else {
    effect_node.filters = effect.Filter().AsCcFilterOperations();
  }
  effect_node.double_sided = !transform.IsBackfaceHidden();
  effect_node.effect_changed = effect.NodeChangeAffectsRaster();

  effect_node.view_transition_element_resource_id =
      effect.ViewTransitionElementResourceId();

  effect_node.subtree_capture_id =
      viz::SubtreeCaptureId(*effect.ElementCaptureId());
}

void PropertyTreeManager::UpdateConditionalRenderSurfaceReasons(
    const cc::LayerList& layers) {
  // This vector is indexed by effect node id. The value is the number of
  // layers and sub-render-surfaces controlled by this effect.
  wtf_size_t tree_size = base::checked_cast<wtf_size_t>(effect_tree_.size());
  Vector<int> effect_layer_counts(tree_size);
  Vector<bool> has_child_surface(tree_size);
  // Initialize the vector to count directly controlled layers.
  for (const auto& layer : layers) {
    if (layer->draws_content())
      effect_layer_counts[layer->effect_tree_index()]++;
  }

  // In the effect tree, parent always has lower id than children, so the
  // following loop will check descendants before parents and accumulate
  // effect_layer_counts.
  for (int id = tree_size - 1; id > cc::kSecondaryRootPropertyNodeId; id--) {
    auto* effect = effect_tree_.Node(id);
    if (effect_layer_counts[id] < 2 &&
        IsConditionalRenderSurfaceReason(effect->render_surface_reason) &&
        // kBlendModeDstIn should create a render surface if the mask itself
        // has any child render surface.
        !(effect->render_surface_reason ==
              cc::RenderSurfaceReason::kBlendModeDstIn &&
          has_child_surface[id])) {
      // The conditional render surface can be omitted because it controls less
      // than two layers or render surfaces.
      effect->render_surface_reason = cc::RenderSurfaceReason::kNone;
    }

    // We should not have visited the parent.
    DCHECK_NE(-1, effect_layer_counts[effect->parent_id]);
    if (effect->HasRenderSurface()) {
      // A sub-render-surface counts as one controlled layer of the parent.
      effect_layer_counts[effect->parent_id]++;
      has_child_surface[effect->parent_id] = true;
    } else {
      // Otherwise all layers count as controlled layers of the parent.
      effect_layer_counts[effect->parent_id] += effect_layer_counts[id];
      has_child_surface[effect->parent_id] |= has_child_surface[id];
    }

#if DCHECK_IS_ON()
    // Mark we have visited this effect.
    effect_layer_counts[id] = -1;
#endif
  }
}

// This is called after all property nodes have been converted and we know
// pixel_moving_filter_id for the pixel-moving clip expanders.
void PropertyTreeManager::UpdatePixelMovingFilterClipExpanders() {
  for (const auto& clip : pixel_moving_filter_clip_expanders_) {
    DCHECK(clip->PixelMovingFilter());
    cc::ClipNode* cc_clip =
        clip_tree_.Node(clip->CcNodeId(new_sequence_number_));
    DCHECK(cc_clip);
    cc_clip->pixel_moving_filter_id =
        clip->PixelMovingFilter()->CcNodeId(new_sequence_number_);
    // No DCHECK(!cc_clip->AppliesLocalClip()) because the PixelMovingFilter
    // may not be composited, and the clip node is a no-op node.
  }
  pixel_moving_filter_clip_expanders_.clear();
}

}  // namespace blink

WTF_ALLOW_MOVE_AND_INIT_WITH_MEM_FUNCTIONS(blink::PendingClip)
```