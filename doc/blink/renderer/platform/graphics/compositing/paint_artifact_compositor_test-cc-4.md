Response:
The user wants a summary of the functionality of the provided C++ code snippet from `paint_artifact_compositor_test.cc`. The code consists of several test cases for the `PaintArtifactCompositor` class within the Chromium Blink rendering engine.

I need to:
1. **Identify the core purpose of the tests**: The tests seem to focus on how rounded clips are handled during compositing, particularly when these clips are "synthesized" (implicitly created).
2. **List the specific scenarios tested**: Each `TEST_P` function represents a distinct scenario. I need to understand what each test is verifying.
3. **Relate the functionality to web technologies**: I need to explain how the tested scenarios relate to HTML, CSS, and JavaScript. This likely involves discussing how CSS `border-radius` and `clip-path` properties are handled during rendering.
4. **Infer logical inputs and outputs**:  For each test, I can deduce the input (the defined rounded rectangles, filters, etc.) and the expected output (the structure of the composited layers and property trees).
5. **Identify potential user/developer errors**: Based on the test names and logic, I can infer common mistakes related to using rounded corners and clipping.
6. **Summarize the overall functionality**: I need to synthesize the information from the individual tests into a concise description of the file's purpose.

**Mental Sandbox:**

* **Test case analysis:** I'll go through each `TEST_P` and identify the key elements being tested (e.g., single rounded clip, nested clips, clips with filters, clip sharing).
* **Web technology mapping:**  I'll connect these scenarios to CSS properties like `border-radius`, `clip-path`, `opacity`, `filter`, and `backdrop-filter`.
* **Input/Output examples:** I'll use the provided code to illustrate input and the asserted layer structure as the output.
* **Error examples:**  I can think of user errors like incorrect `border-radius` syntax or misunderstanding how compositing affects clipping. Developer errors might involve incorrect setup of paint artifacts.
* **Summary generation:** I'll combine the individual test purposes into a higher-level description of the file's functionality.

Strategizing complete. I will now generate the response by following the identified steps.
这是`blink/renderer/platform/graphics/compositing/paint_artifact_compositor_test.cc`文件的第 5 部分，主要关注于测试 `PaintArtifactCompositor` 类在处理**合成裁剪 (Synthesized Clip)** 时的行为。合成裁剪通常指的是由引擎自动创建的裁剪，而不是直接由开发者指定的裁剪。

**主要功能归纳 (基于第 5 部分)**:

* **测试合成裁剪的基本情况:** 验证对于简单的、需要裁剪的图层，`PaintArtifactCompositor` 是否能正确地创建和应用合成的圆角裁剪。
* **测试非对称圆角的处理:** 检验当圆角的各个角半径不相等时，`PaintArtifactCompositor` 是否正确降级使用遮罩层 (mask layer) 来实现裁剪。
* **测试嵌套的合成裁剪:** 验证当存在多层嵌套的合成圆角裁剪时，`PaintArtifactCompositor` 是否能正确处理图层的结构和属性树。
* **测试不可绘制图层的合成裁剪:** 验证当需要裁剪的图层本身不绘制内容时，`PaintArtifactCompositor` 是否能正确处理，例如不创建额外的裁剪遮罩层。
* **测试合成裁剪的重用:** 检验在多次更新渲染树时，如果裁剪属性没有变化，`PaintArtifactCompositor` 是否能够重用之前创建的合成裁剪相关的资源。
* **测试通过 `clip-path` 间接触发的合成裁剪:** 验证当对一个已合成的元素应用 `clip-path` 时，`PaintArtifactCompositor` 是否能正确创建合成裁剪。
* **测试连续图层的合成裁剪共享:** 检验当连续的多个已合成图层具有相同的合成圆角裁剪时，`PaintArtifactCompositor` 是否能够共享同一个合成裁剪遮罩层以优化性能。
* **测试非连续图层的合成裁剪:** 验证当具有相同合成圆角裁剪的图层不连续时（中间有其他图层），`PaintArtifactCompositor` 是否会为它们分别创建合成裁剪。
* **测试跨子 Effect 节点的合成裁剪共享:** 检验当前后图层具有相同的合成裁剪，并且中间有一个 Effect 节点时，是否能够共享合成裁剪。
* **测试合成裁剪尊重 Output Clip:** 验证即使图层具有相同的合成圆角裁剪，如果它们被包含在一个具有不同裁剪效果的 Effect 节点中，它们是否会使用独立的合成裁剪。
* **测试合成裁剪代理混合模式 (Delegate Blending):** 验证当一个 Effect 节点具有非标准的混合模式时，是否会阻止其兄弟节点共享合成裁剪，因为混合模式需要由最外层的遮罩层应用。
* **测试合成裁剪代理背景滤镜 (Delegate Backdrop Filter):** 验证当一个 Effect 节点具有背景滤镜时，是否会阻止其兄弟节点共享合成裁剪，因为背景滤镜需要在正确的变换空间中由最外层的遮罩层应用。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这些测试直接关系到 CSS 属性 `border-radius` 和 `clip-path` 的渲染实现。

* **`border-radius`:**  CSS 的 `border-radius` 属性用于创建圆角。当一个元素被提升为合成层（例如，由于使用了 transform, opacity 等 CSS 属性），且应用了 `border-radius`，`PaintArtifactCompositor` 可能会创建合成裁剪来实现圆角效果。
    * **举例:**  一个 `div` 元素设置了 `border-radius: 10px;` 和 `transform: translateZ(0);`，这会导致该 `div` 成为合成层，并可能触发合成裁剪。
* **`clip-path`:** CSS 的 `clip-path` 属性用于定义元素的裁剪区域。当对一个合成层应用 `clip-path` 时，`PaintArtifactCompositor` 需要创建一个合成裁剪来实现裁剪效果。
    * **举例:** 一个 `img` 元素设置了 `clip-path: circle(50%);` 和 `opacity: 0.9;`，这会导致该 `img` 成为合成层，并触发合成裁剪以实现圆形裁剪。

**逻辑推理、假设输入与输出:**

以 `SynthesizedClipShaderBasedBorderRadiusNotSupported2` 测试为例：

* **假设输入:**
    * 一个 `gfx::RectF(50, 50, 300, 200)` 的矩形区域。
    * 一个非对称圆角 `FloatRoundedRect`，左上角和左下角半径为 30，右上角和右下角半径为 40。
    * 一个在上述裁剪区域内绘制黑色矩形的 `TestPaintArtifact`。
* **逻辑推理:** 由于圆角半径不对称，无法使用基于 Shader 的简单圆角裁剪，因此 `PaintArtifactCompositor` 会回退到使用遮罩层来实现裁剪。
* **预期输出:**
    * 创建两个 `cc::Layer`：一个用于内容 (content0)，一个用于裁剪遮罩 (clip_mask0)。
    * `clip_mask0` 的尺寸为裁剪区域加上一些偏移 (`gfx::Size(304, 204)`，`gfx::Vector2dF(48, 48)`)。
    * `clip_mask0` 的 Effect 节点的混合模式为 `SkBlendMode::kDstIn`，用于作为内容层的遮罩。
    * 内容层 (content0) 的 Effect 节点拥有一个 `mask_isolation_0`，其父节点为 `e0`，混合模式为 `SkBlendMode::kSrcOver`，并且 `HasRenderSurface()` 为 true。

**用户或编程常见的使用错误举例:**

* **不理解合成层的影响:** 开发者可能不理解某些 CSS 属性（如 `transform`, `opacity`, `filter`）会将元素提升为合成层，从而触发不同的渲染路径，包括合成裁剪。如果过度使用这些属性，可能会导致不必要的合成层和性能问题。
* **过度使用复杂的 `clip-path`:**  复杂的 `clip-path` 可能会导致性能开销，尤其是在动画过程中。开发者应该尽量使用简单的 `clip-path` 或考虑其他优化方案。
* **不必要的圆角嵌套:**  如果多个嵌套的元素都设置了圆角，可能会导致创建多个合成裁剪，增加渲染负担。开发者应该根据实际需求设置圆角。
* **在不支持 Shader 圆角的环境中使用非对称圆角:**  在某些平台上，非对称圆角可能无法通过高效的 Shader 实现，会回退到性能较低的遮罩层方式。开发者应该了解目标平台的限制。

总而言之，这部分测试旨在确保 `PaintArtifactCompositor` 能够正确高效地处理各种涉及合成裁剪的场景，尤其是在处理圆角和 `clip-path` 这两个常见的 CSS 属性时。它涵盖了从最基本的情况到更复杂的情况，包括性能优化（如裁剪的重用）和不同渲染机制的选择（如 Shader 圆角 vs. 遮罩层）。

### 提示词
```
这是目录为blink/renderer/platform/graphics/compositing/paint_artifact_compositor_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第5部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
_P(PaintArtifactCompositorTest,
       SynthesizedClipShaderBasedBorderRadiusNotSupported2) {
  // This tests the simplest case that a single layer needs to be clipped
  // by a single composited rounded clip. Because the radius is unsymmetric,
  // it falls back to a mask layer.
  FloatRoundedRect rrect(gfx::RectF(50, 50, 300, 200), 30, 40);
  auto* c1 = CreateClip(c0(), t0(), rrect);

  TestPaintArtifact artifact;
  artifact.Chunk(t0(), *c1, e0())
      .RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kBlack);
  Update(artifact.Build());

  // Expectation in effect stack diagram:
  //             clip_mask0
  // content0 [ mask_effect_0 ]
  // [    mask_isolation_0    ]
  // [           e0           ]
  // One content layer.
  ASSERT_EQ(2u, LayerCount());
  ASSERT_EQ(1u, SynthesizedClipLayerCount());

  const cc::Layer* content0 = LayerAt(0);
  const cc::Layer* clip_mask0 = LayerAt(1);

  int c1_id = content0->clip_tree_index();
  const cc::ClipNode& cc_c1 = *GetPropertyTrees().clip_tree().Node(c1_id);
  EXPECT_EQ(gfx::RectF(50, 50, 300, 200), cc_c1.clip);
  ASSERT_EQ(c0_id, cc_c1.parent_id);
  int mask_isolation_0_id = content0->effect_tree_index();
  const cc::EffectNode& mask_isolation_0 =
      *GetPropertyTrees().effect_tree().Node(mask_isolation_0_id);
  ASSERT_EQ(e0_id, mask_isolation_0.parent_id);
  EXPECT_EQ(SkBlendMode::kSrcOver, mask_isolation_0.blend_mode);
  EXPECT_TRUE(mask_isolation_0.HasRenderSurface());

  EXPECT_EQ(SynthesizedClipLayerAt(0), clip_mask0);
  EXPECT_TRUE(clip_mask0->draws_content());
  EXPECT_EQ(cc::HitTestOpaqueness::kMixed, clip_mask0->hit_test_opaqueness());
  EXPECT_EQ(gfx::Size(304, 204), clip_mask0->bounds());
  EXPECT_EQ(gfx::Vector2dF(48, 48), clip_mask0->offset_to_transform_parent());
  EXPECT_EQ(c0_id, clip_mask0->clip_tree_index());
  int mask_effect_0_id = clip_mask0->effect_tree_index();
  const cc::EffectNode& mask_effect_0 =
      *GetPropertyTrees().effect_tree().Node(mask_effect_0_id);
  ASSERT_EQ(mask_isolation_0_id, mask_effect_0.parent_id);
  EXPECT_EQ(SkBlendMode::kDstIn, mask_effect_0.blend_mode);

  // The masks DrawsContent because it has content that it masks which also
  // DrawsContent.
  EXPECT_TRUE(clip_mask0->draws_content());
}

TEST_P(
    PaintArtifactCompositorTest,
    SynthesizedClipSimpleShaderBasedBorderRadiusNotSupportedMacNonEqualCorners) {
  // Tests that on Mac, we fall back to a mask layer if the corners are not all
  // the same radii.
  gfx::SizeF corner(30, 30);
  FloatRoundedRect rrect(gfx::RectF(50, 50, 300, 200), corner, corner, corner,
                         gfx::SizeF());
  auto* c1 = CreateClip(c0(), t0(), rrect);

  TestPaintArtifact artifact;
  artifact.Chunk(t0(), *c1, e0())
      .RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kBlack);
  Update(artifact.Build());

#if BUILDFLAG(IS_MAC)
  ASSERT_EQ(2u, LayerCount());
#else
  ASSERT_EQ(1u, LayerCount());
#endif
}

TEST_P(PaintArtifactCompositorTest, SynthesizedClipNested) {
  // This tests the simplest case that a single layer needs to be clipped
  // by a single composited rounded clip.
  FloatRoundedRect rrect(gfx::RectF(50, 50, 300, 200), 5);
  auto* c1 = CreateClip(c0(), t0(), rrect);
  auto* c2 = CreateClip(*c1, t0(), rrect);
  auto* c3 = CreateClip(*c2, t0(), rrect);
  auto* t1 = CreateTransform(t0(), gfx::Transform(), gfx::Point3F(),
                             CompositingReason::kWillChangeTransform);
  CompositorFilterOperations filter_operations;
  filter_operations.AppendBlurFilter(5);
  auto* filter = CreateFilterEffect(e0(), t0(), c1, filter_operations);

  TestPaintArtifact artifact;
  artifact.Chunk(t0(), *c1, *filter)
      .RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kBlack);
  artifact.Chunk(*t1, *c3, *filter)
      .RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kBlack);
  Update(artifact.Build());

  // Expectation in effect stack diagram:
  //               content1
  //          [ mask_isolation_2 ]
  // content0 [ mask_isolation_1 ]
  // [          filter           ]
  // [     mask_isolation_0      ]
  // [            e0             ]
  // Two content layers.
  ///
  // mask_isolation_1 will have a render surface. mask_isolation_2 will not
  // because non-leaf synthetic rounded clips must have a render surface.
  // mask_isolation_0 will not because it is a leaf synthetic rounded clip
  // in the render surface created by the filter.

  ASSERT_EQ(2u, LayerCount());
  // There is still a "synthesized layer" but it's null.
  ASSERT_EQ(3u, SynthesizedClipLayerCount());
  EXPECT_FALSE(SynthesizedClipLayerAt(0));
  EXPECT_FALSE(SynthesizedClipLayerAt(1));
  EXPECT_FALSE(SynthesizedClipLayerAt(2));

  const cc::Layer* content0 = LayerAt(0);
  const cc::Layer* content1 = LayerAt(1);

  constexpr int c1_id = 2;
  constexpr int e1_id = 2;

  int c3_id = content1->clip_tree_index();
  const cc::ClipNode& cc_c3 = *GetPropertyTrees().clip_tree().Node(c3_id);
  EXPECT_EQ(gfx::RectF(50, 50, 300, 200), cc_c3.clip);
  const cc::ClipNode& cc_c2 =
      *GetPropertyTrees().clip_tree().Node(cc_c3.parent_id);
  EXPECT_EQ(gfx::RectF(50, 50, 300, 200), cc_c2.clip);
  ASSERT_EQ(c1_id, cc_c2.parent_id);
  const cc::ClipNode& cc_c1 = *GetPropertyTrees().clip_tree().Node(c1_id);
  EXPECT_EQ(c1_id, content0->clip_tree_index());
  EXPECT_EQ(gfx::RectF(50, 50, 300, 200), cc_c1.clip);
  ASSERT_EQ(c0_id, cc_c1.parent_id);

  int mask_isolation_2_id = content1->effect_tree_index();
  const cc::EffectNode& mask_isolation_2 =
      *GetPropertyTrees().effect_tree().Node(mask_isolation_2_id);
  const cc::EffectNode& mask_isolation_1 =
      *GetPropertyTrees().effect_tree().Node(mask_isolation_2.parent_id);
  const cc::EffectNode& cc_filter =
      *GetPropertyTrees().effect_tree().Node(mask_isolation_1.parent_id);
  const cc::EffectNode& mask_isolation_0 =
      *GetPropertyTrees().effect_tree().Node(cc_filter.parent_id);

  ASSERT_EQ(e0_id, mask_isolation_0.parent_id);
  EXPECT_EQ(SkBlendMode::kSrcOver, mask_isolation_0.blend_mode);
  EXPECT_TRUE(mask_isolation_0.is_fast_rounded_corner);
  EXPECT_EQ(gfx::RRectF(50, 50, 300, 200, 5),
            mask_isolation_0.mask_filter_info.rounded_corner_bounds());
  EXPECT_FALSE(mask_isolation_0.HasRenderSurface());

  ASSERT_EQ(e1_id, cc_filter.parent_id);
  EXPECT_EQ(cc_filter.id, content0->effect_tree_index());
  EXPECT_EQ(SkBlendMode::kSrcOver, cc_filter.blend_mode);
  EXPECT_FALSE(cc_filter.is_fast_rounded_corner);
  EXPECT_TRUE(cc_filter.HasRenderSurface());

  EXPECT_EQ(SkBlendMode::kSrcOver, mask_isolation_1.blend_mode);
  EXPECT_TRUE(mask_isolation_1.is_fast_rounded_corner);
  EXPECT_EQ(gfx::RRectF(50, 50, 300, 200, 5),
            mask_isolation_1.mask_filter_info.rounded_corner_bounds());
  EXPECT_TRUE(mask_isolation_1.HasRenderSurface());

  EXPECT_EQ(SkBlendMode::kSrcOver, mask_isolation_2.blend_mode);
  EXPECT_TRUE(mask_isolation_2.is_fast_rounded_corner);
  EXPECT_EQ(gfx::RRectF(50, 50, 300, 200, 5),
            mask_isolation_2.mask_filter_info.rounded_corner_bounds());
  EXPECT_FALSE(mask_isolation_2.HasRenderSurface());
}

TEST_P(PaintArtifactCompositorTest, SynthesizedClipIsNotDrawable) {
  // This tests the simplist case that a single layer needs to be clipped
  // by a single composited rounded clip.
  FloatRoundedRect rrect(gfx::RectF(50, 50, 300, 200), 5);
  auto* c1 = CreateClip(c0(), t0(), rrect);

  TestPaintArtifact artifact;
  artifact.Chunk(t0(), *c1, e0())
      .RectDrawing(gfx::Rect(0, 0, 0, 0), Color::kBlack);
  Update(artifact.Build());

  // Expectation in effect stack diagram:
  //       content0
  // [ mask_isolation_0 ]
  // [        e0        ]
  // One content layer, no clip mask (because layer doesn't draw content).
  ASSERT_EQ(1u, LayerCount());
  ASSERT_EQ(1u, SynthesizedClipLayerCount());
  // There is a synthesized clip", but it has no layer backing.
  ASSERT_EQ(nullptr, SynthesizedClipLayerAt(0));

  const cc::Layer* content0 = LayerAt(0);

  int c1_id = content0->clip_tree_index();
  const cc::ClipNode& cc_c1 = *GetPropertyTrees().clip_tree().Node(c1_id);
  EXPECT_EQ(gfx::RectF(50, 50, 300, 200), cc_c1.clip);
  ASSERT_EQ(c0_id, cc_c1.parent_id);
  int mask_isolation_0_id = content0->effect_tree_index();
  const cc::EffectNode& mask_isolation_0 =
      *GetPropertyTrees().effect_tree().Node(mask_isolation_0_id);
  ASSERT_EQ(e0_id, mask_isolation_0.parent_id);
  EXPECT_EQ(SkBlendMode::kSrcOver, mask_isolation_0.blend_mode);
}

TEST_P(PaintArtifactCompositorTest, ReuseSyntheticClip) {
  // This tests the simplist case that a single layer needs to be clipped
  // by a single composited rounded clip.
  FloatRoundedRect rrect(gfx::RectF(50, 50, 300, 200), 5);
  auto* c1 = CreateClip(c0(), t0(), rrect);
  auto* c2 = CreateClip(c0(), t0(), rrect);

  TestPaintArtifact artifact;
  artifact.Chunk(t0(), *c1, e0())
      .RectDrawing(gfx::Rect(0, 0, 0, 0), Color::kBlack);
  Update(artifact.Build());

  const cc::Layer* content0 = LayerAt(0);

  cc::ElementId old_element_id = GetPropertyTrees()
                                     .effect_tree()
                                     .Node(content0->effect_tree_index())
                                     ->element_id;

  TestPaintArtifact repeated_artifact;
  repeated_artifact.Chunk(t0(), *c1, e0())
      .RectDrawing(gfx::Rect(0, 0, 0, 0), Color::kBlack);
  Update(repeated_artifact.Build());
  const cc::Layer* content1 = LayerAt(0);

  // Check that stable ids are reused across updates.
  EXPECT_EQ(GetPropertyTrees()
                .effect_tree()
                .Node(content1->effect_tree_index())
                ->element_id,
            old_element_id);

  TestPaintArtifact changed_artifact;
  changed_artifact.Chunk(t0(), *c2, e0())
      .RectDrawing(gfx::Rect(0, 0, 0, 0), Color::kBlack);
  Update(changed_artifact.Build());
  const cc::Layer* content2 = LayerAt(0);

  // The new artifact changed the clip node to c2, so the synthetic clip should
  // not be reused.
  EXPECT_NE(GetPropertyTrees()
                .effect_tree()
                .Node(content2->effect_tree_index())
                ->element_id,
            old_element_id);
}

TEST_P(PaintArtifactCompositorTest,
       SynthesizedClipIndirectlyCompositedClipPath) {
  // This tests the case that a clip node needs to be synthesized due to
  // applying clip path to a composited effect.
  auto* c1 = CreateClipPathClip(c0(), t0(), FloatRoundedRect(50, 50, 300, 200));
  auto* e1 = CreateOpacityEffect(e0(), t0(), c1, 1,
                                 CompositingReason::kWillChangeOpacity);

  TestPaintArtifact artifact;
  artifact.Chunk(t0(), *c1, *e1)
      .RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kBlack);
  Update(artifact.Build());

  // Expectation in effect stack diagram:
  // content0   clip_mask0
  // [  e1  ][ mask_effect_0 ]
  // [   mask_isolation_0    ]
  // [          e0           ]
  // One content layer, one clip mask.
  ASSERT_EQ(2u, LayerCount());
  ASSERT_EQ(1u, SynthesizedClipLayerCount());

  const cc::Layer* content0 = LayerAt(0);
  const cc::Layer* clip_mask0 = LayerAt(1);

  int c1_id = content0->clip_tree_index();
  const cc::ClipNode& cc_c1 = *GetPropertyTrees().clip_tree().Node(c1_id);
  EXPECT_EQ(gfx::RectF(50, 50, 300, 200), cc_c1.clip);
  ASSERT_EQ(c0_id, cc_c1.parent_id);
  int e1_id = content0->effect_tree_index();
  const cc::EffectNode& cc_e1 = *GetPropertyTrees().effect_tree().Node(e1_id);
  EXPECT_EQ(c1_id, cc_e1.clip_id);
  int mask_isolation_0_id = cc_e1.parent_id;
  const cc::EffectNode& mask_isolation_0 =
      *GetPropertyTrees().effect_tree().Node(mask_isolation_0_id);
  ASSERT_EQ(e0_id, mask_isolation_0.parent_id);
  EXPECT_EQ(c0_id, mask_isolation_0.clip_id);
  EXPECT_EQ(SkBlendMode::kSrcOver, mask_isolation_0.blend_mode);

  EXPECT_EQ(SynthesizedClipLayerAt(0), clip_mask0);
  EXPECT_EQ(gfx::Size(304, 204), clip_mask0->bounds());
  EXPECT_EQ(gfx::Vector2dF(48, 48), clip_mask0->offset_to_transform_parent());
  EXPECT_EQ(c0_id, clip_mask0->clip_tree_index());
  int mask_effect_0_id = clip_mask0->effect_tree_index();
  const cc::EffectNode& mask_effect_0 =
      *GetPropertyTrees().effect_tree().Node(mask_effect_0_id);
  ASSERT_EQ(mask_isolation_0_id, mask_effect_0.parent_id);
  EXPECT_EQ(c0_id, mask_effect_0.clip_id);
  EXPECT_EQ(SkBlendMode::kDstIn, mask_effect_0.blend_mode);
}

TEST_P(PaintArtifactCompositorTest, SynthesizedClipContiguous) {
  // This tests the case that a two back-to-back composited layers having
  // the same composited rounded clip can share the synthesized mask.
  auto* t1 = CreateTransform(t0(), gfx::Transform(), gfx::Point3F(),
                             CompositingReason::kWillChangeTransform);

  FloatRoundedRect rrect(gfx::RectF(50, 50, 300, 200), 5);
  auto* c1 = CreateClip(c0(), t0(), rrect);

  TestPaintArtifact artifact;
  artifact.Chunk(t0(), *c1, e0())
      .RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kBlack);
  artifact.Chunk(*t1, *c1, e0())
      .RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kBlack);
  Update(artifact.Build());

  // Expectation in effect stack diagram:
  //   content0  content1
  // [  mask_isolation_0  ]
  // [         e0         ]
  // Two content layers, one clip mask.
  ASSERT_EQ(2u, LayerCount());
  // There is still a "synthesized layer" but it's null.
  ASSERT_EQ(1u, SynthesizedClipLayerCount());
  EXPECT_FALSE(SynthesizedClipLayerAt(0));

  const cc::Layer* content0 = LayerAt(0);
  const cc::Layer* content1 = LayerAt(1);

  EXPECT_EQ(t0_id, content0->transform_tree_index());
  int c1_id = content0->clip_tree_index();
  const cc::ClipNode& cc_c1 = *GetPropertyTrees().clip_tree().Node(c1_id);
  EXPECT_EQ(gfx::RectF(50, 50, 300, 200), cc_c1.clip);
  ASSERT_EQ(c0_id, cc_c1.parent_id);
  int mask_isolation_0_id = content0->effect_tree_index();
  const cc::EffectNode& mask_isolation_0 =
      *GetPropertyTrees().effect_tree().Node(mask_isolation_0_id);
  ASSERT_EQ(e0_id, mask_isolation_0.parent_id);
  EXPECT_EQ(SkBlendMode::kSrcOver, mask_isolation_0.blend_mode);

  int t1_id = content1->transform_tree_index();
  const cc::TransformNode& cc_t1 =
      *GetPropertyTrees().transform_tree().Node(t1_id);
  ASSERT_EQ(t0_id, cc_t1.parent_id);
  EXPECT_EQ(c1_id, content1->clip_tree_index());
  EXPECT_EQ(mask_isolation_0_id, content1->effect_tree_index());

  EXPECT_TRUE(mask_isolation_0.is_fast_rounded_corner);
  EXPECT_EQ(gfx::RRectF(50, 50, 300, 200, 5),
            mask_isolation_0.mask_filter_info.rounded_corner_bounds());
  EXPECT_FALSE(mask_isolation_0.HasRenderSurface());
}

TEST_P(PaintArtifactCompositorTest, SynthesizedClipDiscontiguous) {
  // This tests the case that a two composited layers having the same
  // composited rounded clip cannot share the synthesized mask if there is
  // another layer in the middle.
  auto* t1 = CreateTransform(t0(), gfx::Transform(), gfx::Point3F(),
                             CompositingReason::kWillChangeTransform);

  FloatRoundedRect rrect(gfx::RectF(50, 50, 300, 200), 5);
  auto* c1 = CreateClip(c0(), t0(), rrect);

  TestPaintArtifact artifact;
  artifact.Chunk(t0(), *c1, e0())
      .RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kBlack);
  artifact.Chunk(*t1, c0(), e0())
      .RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kBlack);
  artifact.Chunk(t0(), *c1, e0())
      .RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kBlack);
  Update(artifact.Build());

  // Expectation in effect stack diagram:
  //       content0                     content2
  // [ mask_isolation_0 ] content1 [ mask_isolation_1 ]
  // [                       e0                       ]
  // Three content layers.
  ASSERT_EQ(3u, LayerCount());
  // There are still "synthesized layers" but they're null because they use
  // fast rounded corners.
  ASSERT_EQ(2u, SynthesizedClipLayerCount());
  EXPECT_FALSE(SynthesizedClipLayerAt(0));
  EXPECT_FALSE(SynthesizedClipLayerAt(1));

  const cc::Layer* content0 = LayerAt(0);
  const cc::Layer* content1 = LayerAt(1);
  const cc::Layer* content2 = LayerAt(2);

  EXPECT_EQ(t0_id, content0->transform_tree_index());
  int c1_id = content0->clip_tree_index();
  const cc::ClipNode& cc_c1 = *GetPropertyTrees().clip_tree().Node(c1_id);
  EXPECT_EQ(gfx::RectF(50, 50, 300, 200), cc_c1.clip);
  ASSERT_EQ(c0_id, cc_c1.parent_id);
  int mask_isolation_0_id = content0->effect_tree_index();
  const cc::EffectNode& mask_isolation_0 =
      *GetPropertyTrees().effect_tree().Node(mask_isolation_0_id);
  ASSERT_EQ(e0_id, mask_isolation_0.parent_id);
  EXPECT_EQ(SkBlendMode::kSrcOver, mask_isolation_0.blend_mode);
  EXPECT_TRUE(mask_isolation_0.is_fast_rounded_corner);
  EXPECT_EQ(gfx::RRectF(50, 50, 300, 200, 5),
            mask_isolation_0.mask_filter_info.rounded_corner_bounds());
  EXPECT_FALSE(mask_isolation_0.HasRenderSurface());

  int t1_id = content1->transform_tree_index();
  const cc::TransformNode& cc_t1 =
      *GetPropertyTrees().transform_tree().Node(t1_id);
  ASSERT_EQ(t0_id, cc_t1.parent_id);
  EXPECT_EQ(c0_id, content1->clip_tree_index());
  EXPECT_EQ(e0_id, content1->effect_tree_index());

  EXPECT_EQ(t0_id, content2->transform_tree_index());
  EXPECT_EQ(c1_id, content2->clip_tree_index());
  int mask_isolation_1_id = content2->effect_tree_index();
  const cc::EffectNode& mask_isolation_1 =
      *GetPropertyTrees().effect_tree().Node(mask_isolation_1_id);
  EXPECT_NE(mask_isolation_0_id, mask_isolation_1_id);
  ASSERT_EQ(e0_id, mask_isolation_1.parent_id);
  EXPECT_EQ(SkBlendMode::kSrcOver, mask_isolation_1.blend_mode);
  EXPECT_TRUE(mask_isolation_1.is_fast_rounded_corner);
  EXPECT_EQ(gfx::RRectF(50, 50, 300, 200, 5),
            mask_isolation_1.mask_filter_info.rounded_corner_bounds());
  EXPECT_FALSE(mask_isolation_1.HasRenderSurface());
}

TEST_P(PaintArtifactCompositorTest, SynthesizedClipAcrossChildEffect) {
  // This tests the case that an effect having the same output clip as the
  // layers before and after it can share the synthesized mask.
  FloatRoundedRect rrect(gfx::RectF(50, 50, 300, 200), 5);
  auto* c1 = CreateClip(c0(), t0(), rrect);
  auto* e1 = CreateOpacityEffect(e0(), t0(), c1, 1,
                                 CompositingReason::kWillChangeOpacity);

  TestPaintArtifact artifact;
  artifact.Chunk(t0(), *c1, e0())
      .RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kBlack);
  artifact.Chunk(t0(), *c1, *e1)
      .RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kBlack);
  artifact.Chunk(t0(), *c1, e0())
      .RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kBlack);
  Update(artifact.Build());

  // Expectation in effect stack diagram:
  //          content1
  // content0 [  e1  ] content2
  // [    mask_isolation_0    ]
  // [           e0           ]
  // Three content layers.
  ASSERT_EQ(3u, LayerCount());
  // There is still a "synthesized layer" but it's null.
  ASSERT_EQ(1u, SynthesizedClipLayerCount());
  EXPECT_FALSE(SynthesizedClipLayerAt(0));

  const cc::Layer* content0 = LayerAt(0);
  const cc::Layer* content1 = LayerAt(1);
  const cc::Layer* content2 = LayerAt(2);

  int c1_id = content0->clip_tree_index();
  const cc::ClipNode& cc_c1 = *GetPropertyTrees().clip_tree().Node(c1_id);
  EXPECT_EQ(gfx::RectF(50, 50, 300, 200), cc_c1.clip);
  ASSERT_EQ(c0_id, cc_c1.parent_id);
  int mask_isolation_0_id = content0->effect_tree_index();
  const cc::EffectNode& mask_isolation_0 =
      *GetPropertyTrees().effect_tree().Node(mask_isolation_0_id);
  ASSERT_EQ(e0_id, mask_isolation_0.parent_id);
  EXPECT_EQ(SkBlendMode::kSrcOver, mask_isolation_0.blend_mode);
  EXPECT_FALSE(mask_isolation_0.HasRenderSurface());

  EXPECT_EQ(c1_id, content1->clip_tree_index());
  int e1_id = content1->effect_tree_index();
  const cc::EffectNode& cc_e1 = *GetPropertyTrees().effect_tree().Node(e1_id);
  ASSERT_EQ(mask_isolation_0_id, cc_e1.parent_id);

  EXPECT_EQ(c1_id, content2->clip_tree_index());
  EXPECT_EQ(mask_isolation_0_id, content2->effect_tree_index());

  int e2_id = content2->effect_tree_index();
  const cc::EffectNode& cc_e2 = *GetPropertyTrees().effect_tree().Node(e2_id);
  EXPECT_TRUE(cc_e2.is_fast_rounded_corner);
  EXPECT_EQ(gfx::RRectF(50, 50, 300, 200, 5),
            mask_isolation_0.mask_filter_info.rounded_corner_bounds());
}

TEST_P(PaintArtifactCompositorTest, SynthesizedClipRespectOutputClip) {
  // This tests the case that a layer cannot share the synthesized mask despite
  // having the same composited rounded clip if it's enclosed by an effect not
  // clipped by the common clip.
  FloatRoundedRect rrect(gfx::RectF(50, 50, 300, 200), 5);
  auto* c1 = CreateClip(c0(), t0(), rrect);

  CompositorFilterOperations non_trivial_filter;
  non_trivial_filter.AppendBlurFilter(5);
  auto* e1 = CreateFilterEffect(e0(), non_trivial_filter,
                                CompositingReason::kActiveFilterAnimation);

  TestPaintArtifact artifact;
  artifact.Chunk(t0(), *c1, e0())
      .RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kBlack);
  artifact.Chunk(t0(), *c1, *e1)
      .RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kBlack);
  artifact.Chunk(t0(), *c1, e0())
      .RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kBlack);
  Update(artifact.Build());

  // Expectation in effect stack diagram:
  //                           content1
  //       content0      [ mask_isolation_1 ]      content2
  // [ mask_isolation_0 ][        e1        ][ mask_isolation_2  ]
  // [                            e0                             ]
  // Three content layers.
  ASSERT_EQ(3u, LayerCount());
  // There are still "synthesized layers" but they're null because they use
  // fast rounded corners.
  ASSERT_EQ(3u, SynthesizedClipLayerCount());
  EXPECT_FALSE(SynthesizedClipLayerAt(0));
  EXPECT_FALSE(SynthesizedClipLayerAt(1));
  EXPECT_FALSE(SynthesizedClipLayerAt(2));

  const cc::Layer* content0 = LayerAt(0);
  const cc::Layer* content1 = LayerAt(1);
  const cc::Layer* content2 = LayerAt(2);

  int c1_id = content0->clip_tree_index();
  const cc::ClipNode& cc_c1 = *GetPropertyTrees().clip_tree().Node(c1_id);
  EXPECT_EQ(gfx::RectF(50, 50, 300, 200), cc_c1.clip);
  ASSERT_EQ(c0_id, cc_c1.parent_id);
  int mask_isolation_0_id = content0->effect_tree_index();
  const cc::EffectNode& mask_isolation_0 =
      *GetPropertyTrees().effect_tree().Node(mask_isolation_0_id);
  ASSERT_EQ(e0_id, mask_isolation_0.parent_id);
  EXPECT_EQ(SkBlendMode::kSrcOver, mask_isolation_0.blend_mode);
  EXPECT_TRUE(mask_isolation_0.is_fast_rounded_corner);
  EXPECT_EQ(gfx::RRectF(50, 50, 300, 200, 5),
            mask_isolation_0.mask_filter_info.rounded_corner_bounds());
  EXPECT_FALSE(mask_isolation_0.HasRenderSurface());

  EXPECT_EQ(c1_id, content1->clip_tree_index());
  int mask_isolation_1_id = content1->effect_tree_index();
  const cc::EffectNode& mask_isolation_1 =
      *GetPropertyTrees().effect_tree().Node(mask_isolation_1_id);
  EXPECT_NE(mask_isolation_0_id, mask_isolation_1_id);
  EXPECT_EQ(SkBlendMode::kSrcOver, mask_isolation_1.blend_mode);
  int e1_id = mask_isolation_1.parent_id;
  const cc::EffectNode& cc_e1 = *GetPropertyTrees().effect_tree().Node(e1_id);
  ASSERT_EQ(e0_id, cc_e1.parent_id);
  EXPECT_TRUE(mask_isolation_1.is_fast_rounded_corner);
  EXPECT_EQ(gfx::RRectF(50, 50, 300, 200, 5),
            mask_isolation_1.mask_filter_info.rounded_corner_bounds());
  EXPECT_FALSE(mask_isolation_1.HasRenderSurface());

  EXPECT_EQ(c1_id, content2->clip_tree_index());
  int mask_isolation_2_id = content2->effect_tree_index();
  const cc::EffectNode& mask_isolation_2 =
      *GetPropertyTrees().effect_tree().Node(mask_isolation_2_id);
  EXPECT_NE(mask_isolation_0_id, mask_isolation_2_id);
  EXPECT_NE(mask_isolation_1_id, mask_isolation_2_id);
  ASSERT_EQ(e0_id, mask_isolation_2.parent_id);
  EXPECT_EQ(SkBlendMode::kSrcOver, mask_isolation_2.blend_mode);
  EXPECT_TRUE(mask_isolation_2.is_fast_rounded_corner);
  EXPECT_EQ(gfx::RRectF(50, 50, 300, 200, 5),
            mask_isolation_2.mask_filter_info.rounded_corner_bounds());
  EXPECT_FALSE(mask_isolation_2.HasRenderSurface());
}

TEST_P(PaintArtifactCompositorTest, SynthesizedClipDelegateBlending) {
  // This tests the case that an effect with exotic blending cannot share
  // the synthesized mask with its siblings because its blending has to be
  // applied by the outermost mask.
  FloatRoundedRect rrect(gfx::RectF(50, 50, 300, 200), 5);
  auto* c1 = CreateClip(c0(), t0(), rrect);

  EffectPaintPropertyNode::State e1_state;
  e1_state.local_transform_space = &t0();
  e1_state.output_clip = c1;
  e1_state.blend_mode = SkBlendMode::kMultiply;
  e1_state.direct_compositing_reasons = CompositingReason::kWillChangeOpacity;
  auto* e1 = EffectPaintPropertyNode::Create(e0(), std::move(e1_state));

  TestPaintArtifact artifact;
  artifact.Chunk(t0(), *c1, e0())
      .RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kBlack);
  artifact.Chunk(t0(), *c1, *e1)
      .RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kBlack);
  artifact.Chunk(t0(), *c1, e0())
      .RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kBlack);
  Update(artifact.Build());

  // Expectation in effect stack diagram:
  //                     content1
  //       content0      [  e1  ]                     content2
  // [ mask_isolation_0 ][  mask_isolation_1   ][ mask_isolation_2  ]
  // [                              e0                              ]
  // Three content layers.
  ASSERT_EQ(3u, LayerCount());
  // There are still "synthesized layers" but they're null because they use
  // fast rounded corners.
  ASSERT_EQ(3u, SynthesizedClipLayerCount());
  EXPECT_FALSE(SynthesizedClipLayerAt(0));
  EXPECT_FALSE(SynthesizedClipLayerAt(1));
  EXPECT_FALSE(SynthesizedClipLayerAt(2));

  const cc::Layer* content0 = LayerAt(0);
  const cc::Layer* content1 = LayerAt(1);
  const cc::Layer* content2 = LayerAt(2);

  int c1_id = content0->clip_tree_index();
  const cc::ClipNode& cc_c1 = *GetPropertyTrees().clip_tree().Node(c1_id);
  EXPECT_EQ(gfx::RectF(50, 50, 300, 200), cc_c1.clip);
  ASSERT_EQ(c0_id, cc_c1.parent_id);
  int mask_isolation_0_id = content0->effect_tree_index();
  const cc::EffectNode& mask_isolation_0 =
      *GetPropertyTrees().effect_tree().Node(mask_isolation_0_id);
  ASSERT_EQ(e0_id, mask_isolation_0.parent_id);
  EXPECT_EQ(SkBlendMode::kSrcOver, mask_isolation_0.blend_mode);
  EXPECT_TRUE(mask_isolation_0.is_fast_rounded_corner);
  EXPECT_EQ(gfx::RRectF(50, 50, 300, 200, 5),
            mask_isolation_0.mask_filter_info.rounded_corner_bounds());

  EXPECT_EQ(c1_id, content1->clip_tree_index());
  int e1_id = content1->effect_tree_index();
  const cc::EffectNode& cc_e1 = *GetPropertyTrees().effect_tree().Node(e1_id);
  EXPECT_EQ(SkBlendMode::kSrcOver, cc_e1.blend_mode);
  int mask_isolation_1_id = cc_e1.parent_id;
  const cc::EffectNode& mask_isolation_1 =
      *GetPropertyTrees().effect_tree().Node(mask_isolation_1_id);
  EXPECT_NE(mask_isolation_0_id, mask_isolation_1_id);
  ASSERT_EQ(e0_id, mask_isolation_1.parent_id);
  EXPECT_EQ(SkBlendMode::kMultiply, mask_isolation_1.blend_mode);
  EXPECT_TRUE(mask_isolation_1.is_fast_rounded_corner);
  EXPECT_EQ(gfx::RRectF(50, 50, 300, 200, 5),
            mask_isolation_1.mask_filter_info.rounded_corner_bounds());

  EXPECT_EQ(c1_id, content2->clip_tree_index());
  int mask_isolation_2_id = content2->effect_tree_index();
  const cc::EffectNode& mask_isolation_2 =
      *GetPropertyTrees().effect_tree().Node(mask_isolation_2_id);
  EXPECT_NE(mask_isolation_0_id, mask_isolation_2_id);
  EXPECT_NE(mask_isolation_1_id, mask_isolation_2_id);
  ASSERT_EQ(e0_id, mask_isolation_2.parent_id);
  EXPECT_EQ(SkBlendMode::kSrcOver, mask_isolation_0.blend_mode);
  EXPECT_TRUE(mask_isolation_2.is_fast_rounded_corner);
  EXPECT_EQ(gfx::RRectF(50, 50, 300, 200, 5),
            mask_isolation_2.mask_filter_info.rounded_corner_bounds());
}

TEST_P(PaintArtifactCompositorTest, SynthesizedClipDelegateBackdropFilter) {
  // This tests the case that an effect with backdrop filter cannot share
  // the synthesized mask with its siblings because its backdrop filter has to
  // be applied by the outermost mask in the correct transform space.
  FloatRoundedRect rrect(gfx::RectF(50, 50, 300, 200), 5);
  auto* c1 = CreateClip(c0(), t0(), rrect);
  auto* c2 = CreateClip(*c1, t0(), FloatRoundedRect(60, 60, 200, 100));

  auto* t1 = Create2DTranslation(t0(), 10, 20);
  CompositorFilterOperations blur_filter;
  blur_filter.AppendBlurFilter(5);
  auto* e1 = CreateBackdropFilterEffect(e0(), *t1, c2, blur_filter, 0.5f);

  TestPaintArtifact artifact;
  artifact.Chunk(*t1, *c1, e0())
      .RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kBlack);
  artifact.Chunk(*t1, *c2, *e1)
      .RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kBlack);
  artifact.Chunk(*t1, *c1, e0())
      .RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kBlack);
  Update(artifact.Build());

  // Expectation in effect stack diagram:
  //                           content1
  //       content0      [        e1        ]      content2
  // [ mask_isolation_0 ][ mask_isolation_1 ][ mask_isolation_2  ]
  // [                            e0                             ]
  // Three content layers.
  ASSERT_EQ(3u, LayerCount());
  const cc::Layer* content0 = LayerAt(0);
  const cc::Layer* content1 = LayerAt(1);
  const cc::Layer* content2 = LayerAt(2);

  // Three synthesized layers, all are null because they use fast rounded
  // corners.
  ASSERT_EQ(3u, SynthesizedClipLayerCount());
  EXPECT_FALSE(SynthesizedClipLayerAt(0));
  EXPECT_FALSE(SynthesizedClipLayerAt(1));
  EXPECT_FALSE(SynthesizedClipLayerAt(2));

  int t1_id = content0->transform_tree_index();
  EXPECT_EQ(t0_id, GetPropertyTrees().transform_tree().Node(t1_id)->parent_id);
  int c1_id = content0->clip_tree_index();
  const cc::ClipNode& cc_c1 = *GetPropertyTrees().clip_tree().Node(c1_id);
  EXPECT_EQ(gfx::RectF(50, 50, 300, 200), cc_c1.clip);
  ASSERT_EQ(c0_id, cc_c1.parent_id);
  EXPECT_EQ(t0_id, cc_c1.transform_id);
  int mask_isolation_0_id = content0->effect_tree_index();
  const cc::EffectNode& mask_isolation_0 =
      *GetPropertyTrees().effect_tree().Node(mask_isolation_0_id);
  ASSERT_EQ(e0_id, mask_isolation_0.parent_id);
  EXPECT_EQ(t0_id, mask_isolation_0.transform_id);
  EXPECT_EQ(c0_id, mask_isolation_0.clip_id);
  EXPECT_TRUE(mask_isolation_0.backdrop_filters.IsEmpty());
  EXPECT_TRUE(mask_isolation_0.is_fast_rounded_corner);
  EXPECT_EQ(1.0f, mask_isolation_0.opacity);
  EXPECT_EQ(gfx::RRectF(50, 50, 300, 200, 5),
            mask_isolation_0.mask_filter_info.rounded_corner_bounds());

  EXPECT_EQ(t1_id, content1->transform_tree_index());
  int c2_id = content1->clip_tree_index();
  const cc::ClipNode& cc_c2 = *GetPropertyTrees().clip_tree().Node(c2_id);
  EXPECT_EQ(gfx::RectF(60, 60, 200, 100), cc_c2.clip);
  EXPECT_EQ(c1_id, cc_c2.parent_id);
  EXPECT_EQ(t0_id, cc_c2.transform_id);
  int e1_id = content1->effect_tree_index();
  const cc::EffectNode& cc_e1 = *GetPropertyTrees().effect_tree().Node(e1_id);
  EXPECT_TRUE(cc_e1.backdrop_filters.IsEmpty());
  EXPECT_EQ(1.0f, cc_e1.opacity);
  EXPECT_EQ(t1_id, cc_e1.transform_id);
  EXPECT_EQ(c2_id, cc_e1.clip_id);
  EXPECT_FALSE(cc_e1.backdrop_mask_element_id);

  int mask_isolation_1_id = cc_e1.parent_id;
  const cc::EffectNode& mask_isolation_1 =
      *GetPropertyTrees().effect_tree().Node(mask_isolation_1_id);
  EXPECT_NE(mask_isolation_0_id, mask_isolation_1_id);
  ASSERT_EQ(e0_id, mask_isolation_1.parent_id);
  EXPECT_EQ(t1_id, mask_isolation_1.transform_id);
  EXPECT_EQ(c2_id, mask_isolation_1.clip_id);
  EXPECT_FALSE(mask_isolation_1.backdrop_filters.IsEmpty());
  EXPECT_TRUE(mask_isolation_1.is_fast_rounded_corner);
  // Opacity should also be moved to mask_isolation_1.
  EXPECT_EQ(0.5f, mask_isolation_1.opacity);
  EXPECT_EQ(gfx::RRectF(40, 30, 300, 200, 5),
            mask_isolation_1.mask_filter_info.rounded_corner_bounds());

  EXPECT_EQ(t1_id, content2->transform_tree_index());
  EXPECT_EQ(c1_id, content2->clip_tree_index());
  int mask_isolation_2_id = content2->effect_tree_index();
  const cc::EffectNode& mask_isolation_2 =
      *GetPropertyTrees().effect_tree().Node(mask_isolation_2_id);
  EXPECT_NE(mask_isolation_0_id, mask_isolation_2_id);
  EXPECT_NE(mask_isolation_1_id, mask_isolation_2_id);
  ASSERT_EQ(e0_id, mask_isolation_2.parent_id);
  EXPECT_EQ(t0_id, mask_isolation_2.transform_id);
  EXPECT_EQ(c0_id, mask_isolation_2.clip_id);
  EXPECT_TRUE(mask_isolation_2.backdrop_filters.IsEmpty());
  EXPECT_TRUE(mask_isolation_2.is_fast_rounded_corner);
  EXPECT_EQ(1.0f, mask_isolation_2.opacity);
  EXPECT_EQ(gfx::RRectF(50, 50, 300, 200, 5),
            mask_isolation_2.mask_filter_info.rounded_corner_bounds());
}

TEST_P(PaintArtifactCompositorTest, SynthesizedClipMultipleNonBackdropEffects) {
  // This tests the case that multiple non-backdrop effects can share the
  // synthesized mask.
  FloatRoundedRect rrect(gfx::RectF(50, 50, 300, 200),
```