Response:
The user wants a summary of the functionalities of the provided C++ code snippet. This is the 6th part of a 7-part file, implying the need for a cumulative understanding.

The code snippet consists of several test cases within a larger test suite. Each test case focuses on a specific aspect of how the `PaintArtifactCompositor` class in the Blink rendering engine handles different combinations of paint properties (clips, effects, transforms) and drawing commands.

Here's a breakdown of the individual tests and their implications:

1. **`OpacityRenderSurfaces`**:  Tests how render surfaces are created for opacity effects based on the number of compositing children. It sets up a complex effect tree and checks which opacity nodes get render surfaces.

2. **`OpacityRenderSurfacesWithFilterChildren`**: Checks if opacity effects get a render surface when they have filter effects as children.

3. **`OpacityAnimationRenderSurfaces`**: Similar to `OpacityRenderSurfaces`, but focuses on scenarios where opacity is animated.

4. **`OpacityRenderSurfacesWithBackdropChildren`**: Verifies if opacity effects get a render surface when they have backdrop filter effects as children.

5. **`DirectTransformAnimationCausesRenderSurfaceFor2dAxisMisalignedClip`**:  Checks if a direct transform animation on a clip causes the associated effect to have a render surface.

6. **`IndirectTransformAnimationCausesRenderSurfaceFor2dAxisMisalignedClip`**: Similar to the previous test, but with an indirect transform animation.

7. **`OpacityIndirectlyAffectingTwoLayers`**:  Tests if an opacity effect that indirectly affects two composited layers gets a render surface.

8. **`WillChangeOpacityRenderSurfaceWithLayer`**: Examines the creation of render surfaces for opacity effects with the `will-change: opacity` CSS property when there is a composited layer.

9. **`WillChangeOpacityRenderSurfaceWithoutLayer`**:  Similar to the previous test, but when there is no directly associated composited layer.

10. **`OpacityIndirectlyAffectingTwoLayersWithOpacityAnimations`**:  Likely a test similar to `OpacityIndirectlyAffectingTwoLayers` but involving opacity animations. The provided snippet cuts off here.

**Relationship to JavaScript, HTML, CSS:**

These tests directly relate to how CSS properties like `opacity`, `clip-path` (implicitly through rounded rects), `transform`, and `backdrop-filter` are translated into compositing layers and their properties within the rendering pipeline. The `will-change` CSS property is also explicitly tested. The behavior tested here directly impacts how web pages are rendered and how animations and visual effects are implemented.

**Logical Reasoning (with assumptions):**

*   **Assumption:**  The `Create*` functions (e.g., `CreateClip`, `CreateOpacityEffect`, `CreateTransform`) create instances of paint property nodes.
*   **Assumption:** `TestPaintArtifact` is a helper class for building and managing paint artifacts for testing.
*   **Assumption:** `Update()` triggers the compositing process based on the provided paint artifact and viewport properties.
*   **Assumption:** `LayerCount()` returns the number of composited layers.
*   **Assumption:** `LayerAt()` returns a specific composited layer.
*   **Assumption:** `GetPropertyTrees()` provides access to the property trees (transform, clip, effect).

**Example for `OpacityRenderSurfaces`:**

*   **Input (Conceptual):** A paint artifact describing a hierarchy of elements with different opacity effects, some with `CompositingReason::kWillChangeOpacity`.
*   **Output:** The test verifies the number of composited layers and, more importantly, that the effect nodes in the effect tree have the `HasRenderSurface()` flag set correctly based on the compositing structure. For instance, an opacity effect with multiple compositing children is expected to have a render surface.

**User/Programming Errors:**

*   **Incorrect understanding of compositing triggers:** Developers might expect an element with `opacity: 0.5` to always create a new compositing layer, but these tests demonstrate that Blink optimizes this and only creates a new layer when necessary (e.g., due to `will-change`, animations, or certain combinations of effects).
*   **Unexpected rendering performance:** If a developer uses `will-change: opacity` unnecessarily, they might create more compositing layers than needed, potentially impacting performance. These tests help ensure that Blink's compositing logic is efficient.

**Functionality of this Part (Part 6):**

This specific part of the test file focuses on verifying the logic within `PaintArtifactCompositor` that determines when to create render surfaces for opacity effects, especially in conjunction with filters, animations, and the `will-change` property. It ensures that the compositor correctly identifies scenarios requiring a dedicated render surface for proper rendering of visual effects.

这是目录为blink/renderer/platform/graphics/compositing/paint_artifact_compositor_test.cc的chromium blink引擎源代码文件的一部分， 该部分（第6部分，共7部分）的功能主要集中在**测试 `PaintArtifactCompositor` 如何处理和创建与 `opacity` (不透明度) 相关的渲染表面 (render surfaces)**。

以下是该部分功能的详细归纳和举例说明：

**主要功能:**

*   **测试不同情况下 `opacity` 效果是否会创建渲染表面:**  渲染表面是合成器用来缓存图层内容的一种机制，对于某些效果（如复杂的混合模式或滤镜）是必要的。这些测试用例旨在验证 `PaintArtifactCompositor` 能否正确判断在何种 `opacity` 场景下需要创建渲染表面。

**与 JavaScript, HTML, CSS 的关系和举例说明:**

*   **CSS `opacity` 属性:** 这些测试直接关联到 CSS 的 `opacity` 属性。例如，`TEST_P(PaintArtifactCompositorTest, OpacityRenderSurfaces)` 测试了当多个图层应用不同的 `opacity` 值时，合成器如何处理以及是否会为这些 `opacity` 效果创建渲染表面。
    *   **HTML:**  考虑一个包含多个 `<div>` 元素的 HTML 结构。
    *   **CSS:**  部分 `div` 元素应用了 `opacity: 0.5;`，另一些可能应用了 `opacity: 0.8;` 或使用了 `will-change: opacity;`。
    *   **JavaScript:** JavaScript 可以动态修改这些 `opacity` 值，触发合成器的重新计算。
    *   **测试目标:**  这些测试验证了 `PaintArtifactCompositor` 能否正确识别哪些 `opacity` 效果需要独立的渲染表面来保证渲染的正确性。
*   **CSS `filter` 属性:**  `TEST_P(PaintArtifactCompositorTest, OpacityRenderSurfacesWithFilterChildren)` 测试了当 `opacity` 效果的子节点使用了 CSS `filter` 属性（例如模糊效果）时，是否会创建渲染表面。
    *   **HTML:** 一个设置了 `opacity` 的 `div`。
    *   **CSS:** 该 `div` 的子元素应用了 `filter: blur(5px);`。
    *   **测试目标:** 验证合成器是否会为父元素的 `opacity` 效果创建渲染表面，以便正确应用子元素的滤镜效果。
*   **CSS `animation` 或 `transition` (动画):**  `TEST_P(PaintArtifactCompositorTest, OpacityAnimationRenderSurfaces)` 测试了当 `opacity` 值通过 CSS 动画改变时，渲染表面的创建情况。
    *   **HTML:** 一个应用了 `opacity` 动画的元素。
    *   **CSS:**  定义了一个 `opacity` 从 0 到 1 变化的动画。
    *   **测试目标:**  验证合成器在 `opacity` 动画过程中是否正确管理渲染表面的创建和销毁。
*   **CSS `backdrop-filter` 属性:** `TEST_P(PaintArtifactCompositorTest, OpacityRenderSurfacesWithBackdropChildren)` 测试了当 `opacity` 效果的子节点使用了 `backdrop-filter` 时，是否会创建渲染表面。
    *   **HTML:** 一个设置了 `opacity` 的 `div`。
    *   **CSS:** 该 `div` 的子元素应用了 `backdrop-filter: blur(5px);`。
    *   **测试目标:** 验证合成器是否会为父元素的 `opacity` 效果创建渲染表面，以便正确应用子元素的背景滤镜效果。
*   **CSS `transform` 属性 (变换):** `TEST_P(PaintArtifactCompositorTest, DirectTransformAnimationCausesRenderSurfaceFor2dAxisMisalignedClip)` 和 `TEST_P(PaintArtifactCompositorTest, IndirectTransformAnimationCausesRenderSurfaceFor2dAxisMisalignedClip)` 测试了当影响裁剪区域的变换发生动画时，是否会为 `opacity` 效果创建渲染表面。
    *   **HTML:** 一个具有裁剪 (clip) 效果的元素。
    *   **CSS:** 应用了变换动画，例如旋转或缩放，并且可能与 `opacity` 属性结合使用。
    *   **测试目标:** 验证当裁剪区域的变换发生动画时，为了保证渲染的准确性，合成器是否会为相关的 `opacity` 效果创建渲染表面。
*   **CSS `will-change` 属性:** `TEST_P(PaintArtifactCompositorTest, WillChangeOpacityRenderSurfaceWithLayer)` 和 `TEST_P(PaintArtifactCompositorTest, WillChangeOpacityRenderSurfaceWithoutLayer)` 测试了当元素设置了 `will-change: opacity;` 时，是否会影响渲染表面的创建。
    *   **HTML:**  一个可能在未来会改变 `opacity` 属性的元素。
    *   **CSS:**  应用了 `will-change: opacity;`。
    *   **测试目标:**  验证合成器是否会根据 `will-change` 提示预先创建渲染表面，以优化后续的动画或过渡性能。

**逻辑推理 (假设输入与输出):**

*   **假设输入:** 一组 `PaintArtifact` 对象，描述了带有不同 `opacity` 值的元素，以及可能存在的滤镜、动画和变换效果。
*   **输出:**  断言 (ASSERT/EXPECT) 检查生成的合成图层的数量 (`LayerCount()`) 以及特定效果节点 (`EffectNode`) 是否具有渲染表面 (`HasRenderSurface()`)。

    *   例如，在 `TEST_P(PaintArtifactCompositorTest, OpacityRenderSurfaces)` 中，如果一个 `opacity` 效果有多个合成子图层，则期望该效果节点拥有渲染表面。
    *   在 `TEST_P(PaintArtifactCompositorTest, OpacityAnimationRenderSurfaces)` 中，即使 `opacity` 值为 1，但如果存在 `opacity` 动画，相关的效果节点也可能需要渲染表面。

**用户或者编程常见的使用错误 (举例说明):**

*   **过度使用 `will-change: opacity;`:**  开发者可能会为了“优化”性能而滥用 `will-change`，但这会导致不必要的渲染表面创建，反而可能降低性能。这些测试确保了合成器在没有必要的情况下不会创建额外的渲染表面。
*   **对合成行为的误解:**  开发者可能认为简单的 `opacity` 改变不会触发新的合成层，但这些测试展示了在某些情况下（例如与其他效果结合使用时）仍然会创建新的合成层和渲染表面。
*   **动画性能问题:**  如果开发者没有正确理解渲染表面的创建时机，可能会导致动画过程中出现意外的性能瓶颈。这些测试帮助确保 Blink 的合成器能够有效地管理渲染表面，从而提升动画性能。

**该部分的功能归纳:**

总而言之，这部分测试代码的主要目的是**验证 `PaintArtifactCompositor` 在处理 CSS `opacity` 属性以及与其相关的 `filter`, `animation`, `transform`, 和 `will-change` 属性时，能否正确地决定何时以及如何创建渲染表面，以保证渲染结果的正确性和性能**。 它深入测试了 Blink 引擎在处理不透明度效果时的合成逻辑。

Prompt: 
```
这是目录为blink/renderer/platform/graphics/compositing/paint_artifact_compositor_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第6部分，共7部分，请归纳一下它的功能

"""
 5);
  auto* c1 = CreateClip(c0(), t0(), rrect);
  auto* c2 = CreateClip(*c1, t0(), FloatRoundedRect(60, 60, 200, 100));

  auto* e1 = CreateOpacityEffect(e0(), t0(), c2, 0.5,
                                 CompositingReason::kWillChangeOpacity);
  auto* e2 = CreateOpacityEffect(e0(), t0(), c1, 0.75,
                                 CompositingReason::kWillChangeOpacity);

  TestPaintArtifact artifact;
  artifact.Chunk(t0(), *c2, *e1)
      .RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kBlack);
  artifact.Chunk(t0(), *c1, *e2)
      .RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kBlack);
  artifact.Chunk(t0(), c0(), e0())
      .RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kBlack);
  Update(artifact.Build());

  // Expectation in effect stack diagram:
  //  content0  content1  content2
  // [   e1   ][   e2   ]
  // [  mask_isolation  ]
  // [             e0             ]
  // Three content layers.
  ASSERT_EQ(3u, LayerCount());
  const cc::Layer* content0 = LayerAt(0);
  const cc::Layer* content1 = LayerAt(1);
  const cc::Layer* content2 = LayerAt(2);

  // One synthesized layer, which is null because it uses fast rounded corners.
  ASSERT_EQ(1u, SynthesizedClipLayerCount());
  EXPECT_FALSE(SynthesizedClipLayerAt(0));

  int c2_id = content0->clip_tree_index();
  const cc::ClipNode& cc_c2 = *GetPropertyTrees().clip_tree().Node(c2_id);
  int e1_id = content0->effect_tree_index();
  const cc::EffectNode& cc_e1 = *GetPropertyTrees().effect_tree().Node(e1_id);
  int c1_id = content1->clip_tree_index();
  const cc::ClipNode& cc_c1 = *GetPropertyTrees().clip_tree().Node(c1_id);
  int e2_id = content1->effect_tree_index();
  const cc::EffectNode& cc_e2 = *GetPropertyTrees().effect_tree().Node(e2_id);
  int mask_isolation_id = cc_e1.parent_id;
  const cc::EffectNode& mask_isolation =
      *GetPropertyTrees().effect_tree().Node(mask_isolation_id);

  EXPECT_EQ(c2_id, cc_e1.clip_id);
  EXPECT_EQ(0.5f, cc_e1.opacity);
  EXPECT_EQ(gfx::RectF(60, 60, 200, 100), cc_c2.clip);
  ASSERT_EQ(c1_id, cc_c2.parent_id);

  EXPECT_EQ(c1_id, cc_e2.clip_id);
  EXPECT_EQ(mask_isolation_id, cc_e2.parent_id);
  EXPECT_EQ(0.75f, cc_e2.opacity);
  EXPECT_EQ(gfx::RectF(50, 50, 300, 200), cc_c1.clip);
  ASSERT_EQ(c0_id, cc_c1.parent_id);

  ASSERT_EQ(e0_id, mask_isolation.parent_id);
  EXPECT_EQ(c0_id, mask_isolation.clip_id);
  EXPECT_TRUE(mask_isolation.is_fast_rounded_corner);
  EXPECT_EQ(gfx::RRectF(50, 50, 300, 200, 5),
            mask_isolation.mask_filter_info.rounded_corner_bounds());

  EXPECT_EQ(c0_id, content2->clip_tree_index());
  EXPECT_EQ(e0_id, content2->effect_tree_index());
}

TEST_P(PaintArtifactCompositorTest, WillBeRemovedFromFrame) {
  auto* effect = CreateSampleEffectNodeWithElementId();
  TestPaintArtifact artifact;
  artifact.Chunk(t0(), c0(), *effect)
      .RectDrawing(gfx::Rect(100, 100, 200, 100), Color::kBlack);
  Update(artifact.Build());

  ASSERT_EQ(1u, LayerCount());
  WillBeRemovedFromFrame();
  // We would need a fake or mock LayerTreeHost to validate that we
  // unregister all element ids, so just check layer count for now.
  EXPECT_EQ(0u, LayerCount());
}

TEST_P(PaintArtifactCompositorTest, SolidColor) {
  TestPaintArtifact artifact;
  artifact.Chunk()
      .RectDrawing(gfx::Rect(100, 200, 300, 400), Color::kBlack)
      .IsSolidColor();
  Update(artifact.Build());
  ASSERT_EQ(1u, LayerCount());
  auto* layer = LayerAt(0);
  EXPECT_EQ(gfx::Vector2dF(100, 200), layer->offset_to_transform_parent());
  EXPECT_EQ(gfx::Size(300, 400), layer->bounds());
  EXPECT_TRUE(layer->draws_content());
  EXPECT_TRUE(LayerAt(0)->IsSolidColorLayerForTesting());
  EXPECT_EQ(SkColors::kBlack, layer->background_color());
}

TEST_P(PaintArtifactCompositorTest, ContentsNonOpaque) {
  TestPaintArtifact artifact;
  artifact.Chunk().RectDrawing(gfx::Rect(100, 100, 200, 200), Color::kBlack);
  Update(artifact.Build());
  ASSERT_EQ(1u, LayerCount());
  EXPECT_FALSE(LayerAt(0)->contents_opaque());
}

TEST_P(PaintArtifactCompositorTest, ContentsOpaque) {
  TestPaintArtifact artifact;
  artifact.Chunk()
      .RectDrawing(gfx::Rect(100, 100, 200, 200), Color::kBlack)
      .RectKnownToBeOpaque(gfx::Rect(100, 100, 200, 200));
  Update(artifact.Build());
  ASSERT_EQ(1u, LayerCount());
  EXPECT_TRUE(LayerAt(0)->contents_opaque());
}

TEST_P(PaintArtifactCompositorTest, ContentsOpaqueUnitedNonOpaque) {
  TestPaintArtifact artifact;
  artifact.Chunk()
      .RectDrawing(gfx::Rect(100, 100, 210, 210), Color::kBlack)
      .RectKnownToBeOpaque(gfx::Rect(100, 100, 210, 210))
      .Chunk()
      .RectDrawing(gfx::Rect(200, 200, 200, 200), Color::kBlack)
      .RectKnownToBeOpaque(gfx::Rect(200, 200, 200, 200));
  Update(artifact.Build());
  ASSERT_EQ(1u, LayerCount());
  EXPECT_EQ(gfx::Size(300, 300), LayerAt(0)->bounds());
  EXPECT_FALSE(LayerAt(0)->contents_opaque());
}

TEST_P(PaintArtifactCompositorTest, ContentsOpaqueUnitedClippedToOpaque) {
  // Almost the same as ContentsOpaqueUnitedNonOpaque, but with a clip which
  // removes the non-opaque part of the layer, making the layer opaque.
  auto* clip1 = CreateClip(c0(), t0(), FloatRoundedRect(175, 175, 100, 100));
  TestPaintArtifact artifact;
  artifact.Chunk(t0(), *clip1, e0())
      .RectDrawing(gfx::Rect(100, 100, 250, 250), Color::kBlack)
      .RectKnownToBeOpaque(gfx::Rect(100, 100, 210, 210))
      .Chunk(t0(), *clip1, e0())
      .RectDrawing(gfx::Rect(200, 200, 300, 300), Color::kBlack)
      .RectKnownToBeOpaque(gfx::Rect(200, 200, 200, 200));
  Update(artifact.Build());
  ASSERT_EQ(1u, LayerCount());
  EXPECT_EQ(gfx::Size(100, 100), LayerAt(0)->bounds());
  EXPECT_TRUE(LayerAt(0)->contents_opaque());
}

TEST_P(PaintArtifactCompositorTest, ContentsOpaqueUnitedOpaque1) {
  TestPaintArtifact artifact;
  artifact.Chunk()
      .RectDrawing(gfx::Rect(100, 100, 300, 300), Color::kBlack)
      .RectKnownToBeOpaque(gfx::Rect(100, 100, 300, 300))
      .Chunk()
      .RectDrawing(gfx::Rect(200, 200, 200, 200), Color::kBlack)
      .RectKnownToBeOpaque(gfx::Rect(200, 200, 200, 200));
  Update(artifact.Build());
  ASSERT_EQ(1u, LayerCount());
  EXPECT_EQ(gfx::Size(300, 300), LayerAt(0)->bounds());
  EXPECT_TRUE(LayerAt(0)->contents_opaque());
}

TEST_P(PaintArtifactCompositorTest, ContentsOpaqueUnitedWithRoundedClip) {
  // Almost the same as ContentsOpaqueUnitedOpaque1, but the first layer has a
  // rounded clip.
  auto* clip1 = CreateClip(c0(), t0(),
                           FloatRoundedRect(gfx::RectF(175, 175, 100, 100), 5));
  TestPaintArtifact artifact;
  artifact.Chunk(t0(), *clip1, e0())
      .RectDrawing(gfx::Rect(100, 100, 210, 210), Color::kBlack)
      .RectKnownToBeOpaque(gfx::Rect(100, 100, 210, 210))
      .Chunk(t0(), c0(), e0())
      .RectDrawing(gfx::Rect(200, 200, 100, 100), Color::kBlack)
      .RectKnownToBeOpaque(gfx::Rect(200, 200, 100, 100));
  Update(artifact.Build());
  ASSERT_EQ(1u, LayerCount());
  EXPECT_EQ(gfx::Size(125, 125), LayerAt(0)->bounds());
  EXPECT_FALSE(LayerAt(0)->contents_opaque());
}

TEST_P(PaintArtifactCompositorTest, ContentsOpaqueUnitedOpaque2) {
  TestPaintArtifact artifact;
  artifact.Chunk()
      .RectDrawing(gfx::Rect(100, 100, 200, 200), Color::kBlack)
      .RectKnownToBeOpaque(gfx::Rect(100, 100, 200, 200))
      .Chunk()
      .RectDrawing(gfx::Rect(100, 100, 300, 300), Color::kBlack)
      .RectKnownToBeOpaque(gfx::Rect(100, 100, 300, 300));
  Update(artifact.Build());
  ASSERT_EQ(1u, LayerCount());
  EXPECT_EQ(gfx::Size(300, 300), LayerAt(0)->bounds());
  EXPECT_TRUE(LayerAt(0)->contents_opaque());
}

TEST_P(PaintArtifactCompositorTest, DecompositeEffectWithNoOutputClip) {
  // This test verifies effect nodes with no output clip correctly decomposites
  // if there is no compositing reasons.
  auto* clip1 = CreateClip(c0(), t0(), FloatRoundedRect(75, 75, 100, 100));
  auto* effect1 = CreateOpacityEffect(e0(), t0(), nullptr, 0.5);

  TestPaintArtifact artifact;
  artifact.Chunk().RectDrawing(gfx::Rect(50, 50, 100, 100), Color::kGray);
  artifact.Chunk(t0(), *clip1, *effect1)
      .RectDrawing(gfx::Rect(100, 100, 100, 100), Color::kGray);
  Update(artifact.Build());
  ASSERT_EQ(1u, LayerCount());

  const cc::Layer* layer = LayerAt(0);
  EXPECT_EQ(gfx::Vector2dF(50.f, 50.f), layer->offset_to_transform_parent());
  EXPECT_EQ(gfx::Size(125, 125), layer->bounds());
  EXPECT_EQ(1, layer->effect_tree_index());
}

TEST_P(PaintArtifactCompositorTest, CompositedEffectWithNoOutputClip) {
  // This test verifies effect nodes with no output clip but has compositing
  // reason correctly squash children chunks and assign clip node.
  auto* clip1 = CreateClip(c0(), t0(), FloatRoundedRect(75, 75, 100, 100));

  auto* effect1 =
      CreateOpacityEffect(e0(), t0(), nullptr, 0.5, CompositingReason::kAll);

  TestPaintArtifact artifact;
  artifact.Chunk(t0(), c0(), *effect1)
      .RectDrawing(gfx::Rect(50, 50, 100, 100), Color::kGray);
  artifact.Chunk(t0(), *clip1, *effect1)
      .RectDrawing(gfx::Rect(100, 100, 100, 100), Color::kGray);
  Update(artifact.Build());
  ASSERT_EQ(1u, LayerCount());

  const cc::Layer* layer = LayerAt(0);
  EXPECT_EQ(gfx::Vector2dF(50.f, 50.f), layer->offset_to_transform_parent());
  EXPECT_EQ(gfx::Size(125, 125), layer->bounds());
  EXPECT_EQ(1, layer->clip_tree_index());
  EXPECT_EQ(2, layer->effect_tree_index());
}

TEST_P(PaintArtifactCompositorTest, LayerRasterInvalidationWithClip) {
  cc::FakeImplTaskRunnerProvider task_runner_provider_;
  cc::TestTaskGraphRunner task_graph_runner_;
  cc::FakeLayerTreeHostImpl host_impl(&task_runner_provider_,
                                      &task_graph_runner_);
  host_impl.EnsureSyncTree();

  // The layer's painting is initially not clipped.
  auto* clip = CreateClip(c0(), t0(), FloatRoundedRect(10, 20, 300, 400));
  TestPaintArtifact artifact1;
  artifact1.Chunk(t0(), *clip, e0())
      .RectDrawing(gfx::Rect(50, 50, 200, 200), Color::kBlack);
  artifact1.Client(0).Validate();
  artifact1.Client(1).Validate();
  Update(artifact1.Build());
  ASSERT_EQ(1u, LayerCount());

  auto* layer = LayerAt(0);
  EXPECT_EQ(gfx::Vector2dF(50, 50), layer->offset_to_transform_parent());
  EXPECT_EQ(gfx::Size(200, 200), layer->bounds());
  EXPECT_THAT(
      layer->GetPicture(),
      Pointee(DrawsRectangle(gfx::RectF(0, 0, 200, 200), Color::kBlack)));

  // The layer's painting overflows the left, top, right edges of the clip.
  auto& artifact2 = TestPaintArtifact()
                        .Chunk(artifact1.Client(0))
                        .Properties(t0(), *clip, e0())
                        .RectDrawing(artifact1.Client(1),
                                     gfx::Rect(0, 0, 400, 200), Color::kBlack)
                        .Build();
  // Simluate commit to the compositor thread.
  // When doing a full commit, we would call
  // layer_tree_host_->ActivateCommitState() and the second argument would come
  // from layer_tree_host_->active_commit_state(); we use pending_commit_state()
  // just to keep the test code simple.
  layer->PushPropertiesTo(
      layer->CreateLayerImpl(host_impl.sync_tree()).get(),
      *const_cast<const cc::LayerTreeHost&>(GetLayerTreeHost())
           .pending_commit_state(),
      const_cast<const cc::LayerTreeHost&>(GetLayerTreeHost())
          .thread_unsafe_commit_state());
  Update(artifact2);
  ASSERT_EQ(1u, LayerCount());
  ASSERT_EQ(layer, LayerAt(0));

  // Invalidate the first chunk because its transform in layer changed.
  EXPECT_EQ(gfx::Rect(0, 0, 300, 180), layer->update_rect());
  EXPECT_EQ(gfx::Vector2dF(10, 20), layer->offset_to_transform_parent());
  EXPECT_EQ(gfx::Size(300, 180), layer->bounds());
  EXPECT_THAT(
      layer->GetPicture(),
      Pointee(DrawsRectangle(gfx::RectF(0, 0, 390, 180), Color::kBlack)));

  // The layer's painting overflows all edges of the clip.
  auto& artifact3 =
      TestPaintArtifact()
          .Chunk(artifact1.Client(0))
          .Properties(t0(), *clip, e0())
          .RectDrawing(artifact1.Client(1), gfx::Rect(-100, -200, 500, 800),
                       Color::kBlack)
          .Build();
  // Simluate commit to the compositor thread.
  layer->PushPropertiesTo(
      layer->CreateLayerImpl(host_impl.sync_tree()).get(),
      *const_cast<const cc::LayerTreeHost&>(GetLayerTreeHost())
           .pending_commit_state(),
      const_cast<const cc::LayerTreeHost&>(GetLayerTreeHost())
          .thread_unsafe_commit_state());
  Update(artifact3);
  ASSERT_EQ(1u, LayerCount());
  ASSERT_EQ(layer, LayerAt(0));

  // We should not invalidate the layer because the origin didn't change
  // because of the clip.
  EXPECT_EQ(gfx::Rect(), layer->update_rect());
  EXPECT_EQ(gfx::Vector2dF(10, 20), layer->offset_to_transform_parent());
  EXPECT_EQ(gfx::Size(300, 400), layer->bounds());
  EXPECT_THAT(
      layer->GetPicture(),
      Pointee(DrawsRectangle(gfx::RectF(0, 0, 390, 580), Color::kBlack)));
}

// Test that PaintArtifactCompositor creates the correct nodes for the visual
// viewport's page scale and scroll layers to support pinch-zooming.
TEST_P(PaintArtifactCompositorTest, CreatesViewportNodes) {
  auto matrix = MakeScaleMatrix(2);
  TransformPaintPropertyNode::State transform_state{{matrix}};
  transform_state.in_subtree_of_page_scale = false;
  const CompositorElementId compositor_element_id =
      CompositorElementIdFromUniqueObjectId(1);
  transform_state.compositor_element_id = compositor_element_id;

  auto* scale_transform_node = TransformPaintPropertyNode::Create(
      TransformPaintPropertyNode::Root(), std::move(transform_state));

  TestPaintArtifact artifact;
  ViewportProperties viewport_properties;
  viewport_properties.page_scale = scale_transform_node;
  Update(artifact.Build(), viewport_properties);

  const cc::TransformTree& transform_tree = GetPropertyTrees().transform_tree();
  const cc::TransformNode* cc_transform_node =
      transform_tree.FindNodeFromElementId(compositor_element_id);
  EXPECT_TRUE(cc_transform_node);
  EXPECT_EQ(matrix, cc_transform_node->local);
  EXPECT_EQ(gfx::Point3F(), cc_transform_node->origin);
}

// Test that |cc::TransformNode::in_subtree_of_page_scale_layer| is not set on
// the page scale transform node or ancestors, and is set on descendants.
TEST_P(PaintArtifactCompositorTest, InSubtreeOfPageScale) {
  TransformPaintPropertyNode::State ancestor_transform_state;
  ancestor_transform_state.in_subtree_of_page_scale = false;
  auto* ancestor_transform = TransformPaintPropertyNode::Create(
      TransformPaintPropertyNode::Root(), std::move(ancestor_transform_state));

  TransformPaintPropertyNode::State page_scale_transform_state;
  page_scale_transform_state.in_subtree_of_page_scale = false;
  const CompositorElementId page_scale_compositor_element_id =
      CompositorElementIdFromUniqueObjectId(1);
  page_scale_transform_state.compositor_element_id =
      page_scale_compositor_element_id;
  auto* page_scale_transform = TransformPaintPropertyNode::Create(
      *ancestor_transform, std::move(page_scale_transform_state));

  TransformPaintPropertyNode::State descendant_transform_state;
  const CompositorElementId descendant_compositor_element_id =
      CompositorElementIdFromUniqueObjectId(2);
  descendant_transform_state.compositor_element_id =
      descendant_compositor_element_id;
  descendant_transform_state.in_subtree_of_page_scale = true;
  descendant_transform_state.direct_compositing_reasons =
      CompositingReason::kWillChangeTransform;
  auto* descendant_transform = TransformPaintPropertyNode::Create(
      *page_scale_transform, std::move(descendant_transform_state));

  TestPaintArtifact artifact;
  artifact.Chunk(*descendant_transform, c0(), e0())
      .RectDrawing(gfx::Rect(0, 0, 10, 10), Color::kBlack);
  ViewportProperties viewport_properties;
  viewport_properties.page_scale = page_scale_transform;
  Update(artifact.Build(), viewport_properties);

  const cc::TransformTree& transform_tree = GetPropertyTrees().transform_tree();
  const auto* cc_page_scale_transform =
      transform_tree.FindNodeFromElementId(page_scale_compositor_element_id);
  // The page scale node is not in a subtree of the page scale layer.
  EXPECT_FALSE(cc_page_scale_transform->in_subtree_of_page_scale_layer);

  // Ancestors of the page scale node are not in a page scale subtree.
  auto cc_ancestor_id = cc_page_scale_transform->parent_id;
  while (cc_ancestor_id != cc::kInvalidPropertyNodeId) {
    const auto* ancestor = transform_tree.Node(cc_ancestor_id);
    EXPECT_FALSE(ancestor->in_subtree_of_page_scale_layer);
    cc_ancestor_id = ancestor->parent_id;
  }

  // Descendants of the page scale node should be in the page scale subtree.
  const auto* cc_descendant_transform =
      transform_tree.FindNodeFromElementId(descendant_compositor_element_id);
  EXPECT_TRUE(cc_descendant_transform->in_subtree_of_page_scale_layer);
}

// Test that PaintArtifactCompositor pushes page scale to the transform tree.
TEST_P(PaintArtifactCompositorTest, ViewportPageScale) {
  // Create a page scale transform node with a page scale factor of 2.0.
  TransformPaintPropertyNode::State transform_state{{MakeScaleMatrix(2)}};
  transform_state.in_subtree_of_page_scale = false;
  transform_state.compositor_element_id =
      CompositorElementIdFromUniqueObjectId(1);
  auto* scale_transform_node = TransformPaintPropertyNode::Create(
      TransformPaintPropertyNode::Root(), std::move(transform_state));

  // Create a viewport scroll node with container size 20x10 and contents size
  // 27x32.
  ScrollPaintPropertyNode::State scroll_state;
  scroll_state.container_rect = gfx::Rect(5, 5, 20, 10);
  scroll_state.contents_size = gfx::Size(27, 32);
  scroll_state.user_scrollable_vertical = true;
  scroll_state.max_scroll_offset_affected_by_page_scale = true;
  auto scroll_element_id = CompositorElementIdFromUniqueObjectId(
      NewUniqueObjectId(), CompositorElementIdNamespace::kScroll);
  scroll_state.compositor_element_id = scroll_element_id;

  auto* scroll = ScrollPaintPropertyNode::Create(
      ScrollPaintPropertyNode::Root(), std::move(scroll_state));
  auto* scroll_translation =
      CreateScrollTranslation(*scale_transform_node, 0, 0, *scroll);

  TestPaintArtifact artifact;
  artifact.Chunk(*scroll_translation, c0(), e0())
      .RectDrawing(gfx::Rect(0, 0, 10, 10), Color::kBlack);
  ViewportProperties viewport_properties;
  viewport_properties.page_scale = scale_transform_node;
  Update(artifact.Build(), viewport_properties);

  cc::ScrollTree& scroll_tree = GetPropertyTrees().scroll_tree_mutable();
  cc::ScrollNode* cc_scroll_node =
      scroll_tree.FindNodeFromElementId(scroll_element_id);
  auto max_scroll_offset = scroll_tree.MaxScrollOffset(cc_scroll_node->id);
  // The max scroll offset should be scaled by the page scale factor (see:
  // |ScrollTree::MaxScrollOffset|). This adjustment scales the contents from
  // 27x32 to 54x64 so the max scroll offset becomes (54-20)/2 x (64-10)/2.
  EXPECT_EQ(gfx::PointF(17, 27), max_scroll_offset);
}

enum {
  kNoRenderSurface = 0,
  kHasRenderSurface = 1 << 0,
};

#define EXPECT_OPACITY(effect_id, expected_opacity, expected_flags)        \
  do {                                                                     \
    const auto* effect = GetPropertyTrees().effect_tree().Node(effect_id); \
    EXPECT_EQ(expected_opacity, effect->opacity);                          \
    EXPECT_EQ(!!((expected_flags)&kHasRenderSurface),                      \
              effect->HasRenderSurface());                                 \
  } while (false)

TEST_P(PaintArtifactCompositorTest, OpacityRenderSurfaces) {
  //            e
  //         /  |  \
  //       a    b    c -- L4
  //     / \   / \    \
  //    aa ab L2 L3   ca          (L = layer)
  //    |   |          |
  //   L0  L1         L5
  auto* e = CreateOpacityEffect(e0(), 0.1f);
  auto* a = CreateOpacityEffect(*e, 0.2f);
  auto* b =
      CreateOpacityEffect(*e, 0.3f, CompositingReason::kWillChangeOpacity);
  auto* c =
      CreateOpacityEffect(*e, 0.4f, CompositingReason::kWillChangeOpacity);
  auto* aa =
      CreateOpacityEffect(*a, 0.5f, CompositingReason::kWillChangeOpacity);
  auto* ab =
      CreateOpacityEffect(*a, 0.6f, CompositingReason::kWillChangeOpacity);
  auto* ca =
      CreateOpacityEffect(*c, 0.7f, CompositingReason::kWillChangeOpacity);
  auto* t = CreateTransform(t0(), MakeRotationMatrix(90), gfx::Point3F(),
                            CompositingReason::k3DTransform);

  TestPaintArtifact artifact;
  gfx::Rect r(150, 150, 100, 100);
  artifact.Chunk(t0(), c0(), *aa).RectDrawing(r, Color::kWhite);
  artifact.Chunk(t0(), c0(), *ab).RectDrawing(r, Color::kWhite);
  artifact.Chunk(t0(), c0(), *b).RectDrawing(r, Color::kWhite);
  artifact.Chunk(*t, c0(), *b).RectDrawing(r, Color::kWhite);
  artifact.Chunk(t0(), c0(), *c).RectDrawing(r, Color::kWhite);
  artifact.Chunk(t0(), c0(), *ca).RectDrawing(r, Color::kWhite);
  Update(artifact.Build());
  ASSERT_EQ(6u, LayerCount());

  int effect_ids[6];
  for (size_t i = 0; i < LayerCount(); i++)
    effect_ids[i] = LayerAt(i)->effect_tree_index();

  // Effects of layer 0, 1, 5 each has one compositing layer, so don't have
  // render surface.
  EXPECT_OPACITY(effect_ids[0], 0.5f, kNoRenderSurface);
  EXPECT_OPACITY(effect_ids[1], 0.6f, kNoRenderSurface);
  EXPECT_OPACITY(effect_ids[5], 0.7f, kNoRenderSurface);

  // Layer 2 and 3 have the same effect state. The effect has render surface
  // because it has two compositing layers.
  EXPECT_EQ(effect_ids[2], effect_ids[3]);
  EXPECT_OPACITY(effect_ids[2], 0.3f, kHasRenderSurface);

  // Effect |a| has two indirect compositing layers, so has render surface.
  const auto& effect_tree = GetPropertyTrees().effect_tree();
  int id_a = effect_tree.Node(effect_ids[0])->parent_id;
  EXPECT_EQ(id_a, effect_tree.Node(effect_ids[1])->parent_id);
  EXPECT_OPACITY(id_a, 0.2f, kHasRenderSurface);

  // Effect |c| has one direct and one indirect compositing layers, so has
  // render surface.
  EXPECT_OPACITY(effect_ids[4], 0.4f, kHasRenderSurface);

  // |e| has render surface because it has 3 child render surfaces.
  EXPECT_OPACITY(effect_tree.Node(effect_ids[4])->parent_id, 0.1f,
                 kHasRenderSurface);
}

TEST_P(PaintArtifactCompositorTest, OpacityRenderSurfacesWithFilterChildren) {
  auto* opacity = CreateOpacityEffect(e0(), 0.1f);
  CompositorFilterOperations filter;
  filter.AppendBlurFilter(5);
  auto* filter1 = CreateFilterEffect(*opacity, filter,
                                     CompositingReason::kActiveFilterAnimation);
  auto* filter2 = CreateFilterEffect(*opacity, filter,
                                     CompositingReason::kActiveFilterAnimation);

  gfx::Rect r(150, 150, 100, 100);
  Update(TestPaintArtifact()
             .Chunk(t0(), c0(), *filter1)
             .RectDrawing(r, Color::kWhite)
             .Chunk(t0(), c0(), *filter2)
             .RectDrawing(r, Color::kWhite)
             .Build());
  ASSERT_EQ(2u, LayerCount());
  auto filter_id1 = LayerAt(0)->effect_tree_index();
  auto filter_id2 = LayerAt(1)->effect_tree_index();
  EXPECT_OPACITY(filter_id1, 1.f, kHasRenderSurface);
  EXPECT_OPACITY(filter_id2, 1.f, kHasRenderSurface);
  EXPECT_OPACITY(GetPropertyTrees().effect_tree().Node(filter_id1)->parent_id,
                 0.1f, kHasRenderSurface);
}

TEST_P(PaintArtifactCompositorTest, OpacityAnimationRenderSurfaces) {
  // The topologies of the effect tree and layer tree are the same as
  // OpacityRencerSurfaces, except that the layers all have 1.f opacity and
  // active opacity animations.
  //            e
  //         /  |  \
  //       a    b    c -- L4
  //     / \   / \    \
  //    aa ab L2 L3   ca          (L = layer)
  //    |   |          |
  //   L0  L1         L5
  auto* e = CreateAnimatingOpacityEffect(e0());
  auto* a = CreateAnimatingOpacityEffect(*e);
  auto* b = CreateAnimatingOpacityEffect(*e);
  auto* c = CreateAnimatingOpacityEffect(*e);
  auto* aa = CreateAnimatingOpacityEffect(*a);
  auto* ab = CreateAnimatingOpacityEffect(*a);
  auto* ca = CreateAnimatingOpacityEffect(*c);
  auto* t = CreateTransform(t0(), MakeRotationMatrix(90), gfx::Point3F(),
                            CompositingReason::k3DTransform);

  TestPaintArtifact artifact;
  gfx::Rect r(150, 150, 100, 100);
  artifact.Chunk(t0(), c0(), *aa).RectDrawing(r, Color::kWhite);
  artifact.Chunk(t0(), c0(), *ab).RectDrawing(r, Color::kWhite);
  artifact.Chunk(t0(), c0(), *b).RectDrawing(r, Color::kWhite);
  artifact.Chunk(*t, c0(), *b).RectDrawing(r, Color::kWhite);
  artifact.Chunk(t0(), c0(), *c).RectDrawing(r, Color::kWhite);
  artifact.Chunk(t0(), c0(), *ca).RectDrawing(r, Color::kWhite);
  Update(artifact.Build());
  ASSERT_EQ(6u, LayerCount());

  int effect_ids[6];
  for (size_t i = 0; i < LayerCount(); i++)
    effect_ids[i] = LayerAt(i)->effect_tree_index();

  // Effects of layer 0, 1, 5 each has one compositing layer, so don't have
  // render surface.
  EXPECT_OPACITY(effect_ids[0], 1.f, kNoRenderSurface);
  EXPECT_OPACITY(effect_ids[1], 1.f, kNoRenderSurface);
  EXPECT_OPACITY(effect_ids[5], 1.f, kNoRenderSurface);

  // Layer 2 and 3 have the same effect state. The effect has render surface
  // because it has two compositing layers.
  EXPECT_EQ(effect_ids[2], effect_ids[3]);
  EXPECT_OPACITY(effect_ids[2], 1.f, kHasRenderSurface);

  const auto& effect_tree = GetPropertyTrees().effect_tree();
  int id_a = effect_tree.Node(effect_ids[0])->parent_id;
  EXPECT_EQ(id_a, effect_tree.Node(effect_ids[1])->parent_id);
  EXPECT_OPACITY(id_a, 1.f, kHasRenderSurface);

  // Effect |c| has one direct and one indirect compositing layers, so has
  // render surface.
  EXPECT_OPACITY(effect_ids[4], 1.f, kHasRenderSurface);
  EXPECT_OPACITY(effect_tree.Node(effect_ids[4])->parent_id, 1.f,
                 kHasRenderSurface);
}

TEST_P(PaintArtifactCompositorTest, OpacityRenderSurfacesWithBackdropChildren) {
  // Opacity effect with a single compositing backdrop-filter child. Normally
  // the opacity effect would not get a render surface. However, because
  // backdrop-filter needs to only filter up to the backdrop root, it always
  // gets a render surface.
  auto* e = CreateOpacityEffect(e0(), 0.4f);
  auto* a = CreateOpacityEffect(*e, 0.5f);
  CompositorFilterOperations blur_filter;
  blur_filter.AppendBlurFilter(5);
  auto* bd = CreateBackdropFilterEffect(*a, blur_filter);

  TestPaintArtifact artifact;
  gfx::Rect r(150, 150, 100, 100);
  artifact.Chunk(t0(), c0(), *a).RectDrawing(r, Color::kWhite);
  artifact.Chunk(t0(), c0(), *bd).RectDrawing(r, Color::kWhite);
  Update(artifact.Build());
  ASSERT_EQ(2u, LayerCount());

  EXPECT_OPACITY(LayerAt(0)->effect_tree_index(), 0.5, kHasRenderSurface);
  EXPECT_OPACITY(LayerAt(1)->effect_tree_index(), 1.0, kHasRenderSurface);
}

TEST_P(PaintArtifactCompositorTest,
       DirectTransformAnimationCausesRenderSurfaceFor2dAxisMisalignedClip) {
  // When a clip is affected by an animated transform, we should get a render
  // surface for the effect node.
  auto* t1 = CreateAnimatingTransform(t0());
  auto* e1 = CreateOpacityEffect(e0(), *t1, nullptr, 1.f);
  auto* c1 = CreateClip(c0(), t0(), FloatRoundedRect(50, 50, 50, 50));
  TestPaintArtifact artifact;
  gfx::Rect r(150, 150, 100, 100);
  artifact.Chunk(t0(), c0(), e0()).RectDrawing(r, Color::kWhite);
  artifact.Chunk(t0(), *c1, *e1).RectDrawing(r, Color::kWhite);
  Update(artifact.Build());
  ASSERT_EQ(2u, LayerCount());

  const auto* effect =
      GetPropertyTrees().effect_tree().Node(LayerAt(1)->effect_tree_index());
  EXPECT_TRUE(effect->HasRenderSurface());
}

TEST_P(PaintArtifactCompositorTest,
       IndirectTransformAnimationCausesRenderSurfaceFor2dAxisMisalignedClip) {
  // When a clip is affected by an animated transform, we should get a render
  // surface for the effect node.
  auto* t1 = CreateAnimatingTransform(t0());
  auto* t2 = Create2DTranslation(*t1, 10, 20);
  auto* e1 = CreateOpacityEffect(e0(), *t2, nullptr, 1.f);
  auto* c1 = CreateClip(c0(), t0(), FloatRoundedRect(50, 50, 50, 50));
  TestPaintArtifact artifact;
  gfx::Rect r(150, 150, 100, 100);
  artifact.Chunk(t0(), c0(), e0()).RectDrawing(r, Color::kWhite);
  artifact.Chunk(t0(), *c1, *e1).RectDrawing(r, Color::kWhite);
  Update(artifact.Build());
  ASSERT_EQ(2u, LayerCount());

  const auto* effect =
      GetPropertyTrees().effect_tree().Node(LayerAt(1)->effect_tree_index());
  EXPECT_TRUE(effect->HasRenderSurface());
}

TEST_P(PaintArtifactCompositorTest, OpacityIndirectlyAffectingTwoLayers) {
  auto* opacity = CreateOpacityEffect(e0(), 0.5f);
  auto* child_composited_transform = CreateTransform(
      t0(), gfx::Transform(), gfx::Point3F(), CompositingReason::k3DTransform);
  auto* grandchild_composited_transform =
      CreateTransform(*child_composited_transform, gfx::Transform(),
                      gfx::Point3F(), CompositingReason::k3DTransform);
  auto* child_effect = CreateOpacityEffect(*opacity, 1.f);
  auto* grandchild_effect = CreateOpacityEffect(*child_effect, 1.f);

  TestPaintArtifact artifact;
  artifact.Chunk(*child_composited_transform, c0(), *child_effect)
      .RectDrawing(gfx::Rect(150, 150, 100, 100), Color::kWhite);
  artifact.Chunk(*grandchild_composited_transform, c0(), *grandchild_effect)
      .RectDrawing(gfx::Rect(150, 150, 100, 100), Color::kGray);
  Update(artifact.Build());
  ASSERT_EQ(2u, LayerCount());

  const auto& effect_tree = GetPropertyTrees().effect_tree();
  int layer0_effect_id = LayerAt(0)->effect_tree_index();
  EXPECT_OPACITY(layer0_effect_id, 1.f, kNoRenderSurface);
  int layer1_effect_id = LayerAt(1)->effect_tree_index();
  EXPECT_OPACITY(layer1_effect_id, 1.f, kNoRenderSurface);
  // |opacity| affects both layer0 and layer1 which don't have render surfaces,
  // so it should have a render surface.
  int opacity_id = effect_tree.Node(layer0_effect_id)->parent_id;
  EXPECT_OPACITY(opacity_id, 0.5f, kHasRenderSurface);
}

TEST_P(PaintArtifactCompositorTest, WillChangeOpacityRenderSurfaceWithLayer) {
  auto* opacity =
      CreateOpacityEffect(e0(), 1.f, CompositingReason::kWillChangeOpacity);
  auto* child_composited_transform = CreateTransform(
      t0(), gfx::Transform(), gfx::Point3F(), CompositingReason::k3DTransform);
  auto* child_effect = CreateOpacityEffect(*opacity, 1.f);

  TestPaintArtifact artifact;
  artifact.Chunk(t0(), c0(), *opacity)
      .RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kBlack);
  artifact.Chunk(*child_composited_transform, c0(), *child_effect)
      .RectDrawing(gfx::Rect(150, 150, 100, 100), Color::kWhite);
  Update(artifact.Build());
  ASSERT_EQ(2u, LayerCount());

  int layer0_effect_id = LayerAt(0)->effect_tree_index();
  EXPECT_OPACITY(layer0_effect_id, 1.f, kNoRenderSurface);
  int layer1_effect_id = LayerAt(1)->effect_tree_index();
  // TODO(crbug.com/1285498): Optimize for will-change: opacity.
  // EXPECT_OPACITY(layer1_effect_id, 1.f, kHasRenderSurface);
  EXPECT_OPACITY(layer1_effect_id, 1.f, kNoRenderSurface);
}

TEST_P(PaintArtifactCompositorTest,
       WillChangeOpacityRenderSurfaceWithoutLayer) {
  auto* opacity =
      CreateOpacityEffect(e0(), 1.f, CompositingReason::kWillChangeOpacity);
  auto* child_composited_transform = CreateTransform(
      t0(), gfx::Transform(), gfx::Point3F(), CompositingReason::k3DTransform);
  auto* grandchild_composited_transform =
      CreateTransform(*child_composited_transform, gfx::Transform(),
                      gfx::Point3F(), CompositingReason::k3DTransform);
  auto* child_effect = CreateOpacityEffect(*opacity, 1.f);
  auto* grandchild_effect = CreateOpacityEffect(*child_effect, 1.f);

  TestPaintArtifact artifact;
  artifact.Chunk(*child_composited_transform, c0(), *child_effect)
      .RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kBlack);
  artifact.Chunk(*grandchild_composited_transform, c0(), *grandchild_effect)
      .RectDrawing(gfx::Rect(150, 150, 100, 100), Color::kWhite);
  Update(artifact.Build());
  ASSERT_EQ(2u, LayerCount());

  const auto& effect_tree = GetPropertyTrees().effect_tree();
  int layer0_effect_id = LayerAt(0)->effect_tree_index();
  EXPECT_OPACITY(layer0_effect_id, 1.f, kNoRenderSurface);
  int layer1_effect_id = LayerAt(1)->effect_tree_index();
  EXPECT_OPACITY(layer1_effect_id, 1.f, kNoRenderSurface);
  int opacity_id = effect_tree.Node(layer0_effect_id)->parent_id;
  // TODO(crbug.com/1285498): Optimize for will-change: opacity.
  // |opacity| affects both layer0 and layer1 which don't have render surfaces,
  // so it should have a render surface if we have the optimization for
  // will-change:opacity.
  // EXPECT_OPACITY(opacity_id, 1.f, kHasRenderSurface);
  EXPECT_OPACITY(opacity_id, 1.f, kNoRenderSurface);
}

TEST_P(PaintArtifactCompositorTest,
       OpacityIndirectlyAffectingTwoLayersWithOpacityAnimations) {
"""


```