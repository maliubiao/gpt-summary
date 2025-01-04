Response:
The user is asking for a summary of the functionality of the provided C++ code, which is a test file for a component in the Chromium Blink rendering engine. Specifically, they want to understand what the code tests, how it relates to web technologies (JavaScript, HTML, CSS), if there's any logical reasoning with inputs and outputs, common usage errors, and a concise summary of the functionality.

Here's a breakdown of the thought process to generate the response:

1. **Identify the Core Purpose:** The filename `paint_artifact_compositor_test.cc` immediately suggests this file tests the `PaintArtifactCompositor`. The word "compositor" hints at the process of combining different visual elements into a final image, which is central to how web pages are rendered. The `_test` suffix clearly indicates these are automated tests.

2. **Analyze the Test Structure:** The code is structured using Google Test (`TEST_P`). Each `TEST_P` function represents a specific test case. Examining the names of these test cases provides clues about the features being tested. Keywords like "CompositedMask," "NonCompositedMask," "BlendMode," "Clip," "Effect," and "Transform" stand out.

3. **Infer Functionality from Test Names:** By looking at the test names, we can infer the following:
    * **Masking:** Tests related to applying masks to content (`CompositedMask`, `NonCompositedMask`).
    * **Blend Modes:** Tests involving different ways of blending colors (`NonCompositedSimpleExoticBlendMode`, `ForcedCompositedExoticBlendMode`). "Exotic" suggests blend modes beyond the standard ones.
    * **Compositing:** Tests related to the creation of separate composited layers (`CompositedMaskOneChild`, `CompositedMaskTwoChildren`).
    * **Clipping:** Tests focused on how content is clipped (`DecompositeClip`, `SynthesizedClipSimple`).
    * **Effects:** Tests involving visual effects like opacity (`DecompositeEffect`, `DirectlyCompositedEffect`).
    * **Transforms:** Tests concerning transformations like rotation (`SynthesizedClipRotatedNotSupported`).
    * **Opaqueness:** Tests around how compositing affects the perceived opaqueness of elements.
    * **Property Trees:** Mentions of `GetPropertyTrees` indicate tests related to managing the data structures that track visual properties.
    * **Layer Management:** Assertions about `LayerCount()` indicate tests on how the compositor creates and manages rendering layers.
    * **Invisibility:** Tests specifically dealing with elements that are effectively invisible.

4. **Connect to Web Technologies:**
    * **HTML:**  The tests indirectly relate to HTML because the rendered output represents the visual representation of HTML elements. The structure of the tests (parent-child relationships) mirrors the DOM tree.
    * **CSS:**  Many of the tested features are directly controlled by CSS properties. `opacity`, `mask`, `mix-blend-mode`, `clip-path`, and `transform` are all CSS properties.
    * **JavaScript:** While not directly tested here, JavaScript can dynamically modify CSS properties, which in turn would influence the behavior tested in this file. Animations, for example, are mentioned in some test names.

5. **Consider Logical Reasoning (Inputs and Outputs):** Each test case sets up a specific `PaintArtifact` (representing painting instructions) as input and then asserts the resulting state of the compositor (number of layers, properties of those layers, etc.) as the output. A simple example would be a test that creates a masked element and verifies that two layers are created (one for the content, one for the mask).

6. **Identify Potential User/Programming Errors:** Based on the tested features, common errors would include:
    * **Incorrectly using blend modes:** Applying blend modes that require compositing without realizing the performance implications.
    * **Misunderstanding masking:** Expecting masks to behave a certain way without considering compositing behavior.
    * **Over-reliance on compositing:** Forcing unnecessary compositing, leading to performance issues.
    * **Incorrectly applying transforms:** Applying transforms that prevent optimizations like synthesized clips.

7. **Formulate the Summary:**  Combine the observations into a concise summary, highlighting the main areas of functionality tested.

8. **Review and Refine:** Ensure the language is clear, accurate, and addresses all aspects of the user's request. For example, explicitly mentioning the connection to the rendering pipeline and the purpose of the tests in ensuring correctness. Adding details about the structure of the tests (using `PaintArtifact`) also improves understanding.
这是 `blink/renderer/platform/graphics/compositing/paint_artifact_compositor_test.cc` 文件的第 4 部分，该文件是 Chromium Blink 引擎的一部分，专门用于测试 `PaintArtifactCompositor` 类。`PaintArtifactCompositor` 的主要职责是将绘制信息（`PaintArtifact`）转换为渲染所需的图层树（`cc::Layer`）。

**本部分（第 4 部分）的功能归纳：**

本部分主要集中测试了以下 `PaintArtifactCompositor` 的功能：

* **使用合成遮罩 (Composited Mask)：**
    * 测试了当使用 `will-change: opacity` 等属性强制遮罩进行合成时，`PaintArtifactCompositor` 如何创建图层和设置属性树（特别是效果树）。
    * 验证了合成遮罩是否影响被遮罩图层的 `contents_opaque` 和 `contents_opaque_for_text` 属性。
    * 测试了当遮罩只有一个子元素和一个以上子元素时的合成行为，以及是否需要创建渲染表面 (RenderSurface)。
* **使用非合成遮罩 (Non-Composited Mask)：**
    * 测试了当遮罩不进行合成时，`PaintArtifactCompositor` 如何处理，以及这如何清除被遮罩图层的 `contents_opaque` 和 `contents_opaque_for_text` 状态。
* **使用非标准混合模式 (Exotic Blend Mode)：**
    * 测试了当使用 `xor` 等非标准混合模式但不强制合成时，`PaintArtifactCompositor` 会将混合模式降级为 `src_over`，并且不创建额外的渲染表面。
    * 测试了当使用非标准混合模式并强制合成时，`PaintArtifactCompositor` 会创建新的合成图层，并正确设置混合模式和渲染表面。
    * 测试了在有动画或 3D 变换的图层上使用非标准混合模式时的合成行为。
    * 测试了在没有背景的情况下分解非标准混合模式，以及在存在非绘制图层时分解非标准混合模式的情况。
* **更新操作和序列号：**
    * 测试了每次调用 `Update` 方法时，属性树的序列号是否会更新，并且创建的图层的属性树序列号是否与最新的属性树序列号一致。
* **分解裁剪 (Decomposite Clip)：**
    * 测试了裁剪操作如何被分解到图层中，并影响图层的边界和偏移。
* **分解效果 (Decomposite Effect)：**
    * 测试了当效果节点没有直接合成原因时，它可以与其他绘制块合并到同一个图层中。
* **直接合成效果 (Directly Composited Effect)：**
    * 测试了当效果节点有直接合成原因时，`PaintArtifactCompositor` 会创建一个新的合成图层。
* **深度分解效果 (Decomposite Deep Effect)：**
    * 测试了绘制块进入多层效果节点时，`PaintArtifactCompositor` 如何处理合成和分解，以及在遇到强制合成的效果节点时停止分解。
* **间接合成效果 (Indirectly Composited Effect)：**
    * 测试了当某些绘制块需要合成时，即使某些效果节点没有直接合成原因，也可能需要为了分组而进行合成。
* **由于重叠而不合并的分解效果 (Decomposited Effect Not Merging Due To Overlap)：**
    * 测试了即使效果本身可以被分解，但如果它与之前合成的效果重叠，则可能需要单独的 backing 图层。
* **有效不可见的绘制块 (Effectively Invisible Chunk)：**
    * 测试了当绘制块被标记为有效不可见时，`PaintArtifactCompositor` 如何处理，是否创建图层，以及图层属性的设置。
    * 特别测试了有效不可见的绘制块与前面或后面的绘制块合并的情况。
* **管理图层元素 ID (Update Manages Layer Element IDs)：**
    * 测试了 `Update` 方法如何管理与动画变换关联的图层元素 ID 的生命周期。
* **合成裁剪 (Synthesized Clip)：**
    * 测试了当使用圆角矩形裁剪且没有旋转时，`PaintArtifactCompositor` 如何使用合成裁剪优化，避免创建额外的遮罩图层。
    * 测试了当裁剪包含旋转变换时，合成裁剪不被支持，并且会创建额外的遮罩图层。
    * 验证了 90 度旋转被认为是轴对齐的，因此仍然支持合成裁剪。

**与 JavaScript, HTML, CSS 的关系：**

这些测试直接关系到 CSS 的渲染机制，因为许多被测试的功能都源于 CSS 属性的应用：

* **`opacity` (CSS):**  在测试合成遮罩和效果时多次使用，模拟了 CSS `opacity` 属性和 `will-change: opacity` 属性对图层合成的影响。
    * **例子：** `CreateOpacityEffect(e0(), 1.0, CompositingReason::kWillChangeOpacity)`  模拟了设置了 `will-change: opacity` 的元素。
* **`mask` (CSS):**  测试了不同类型的遮罩（合成和非合成）及其对图层结构的影响，这与 CSS `mask` 属性相关。
    * **例子：**  通过 `masking_state.blend_mode = SkBlendMode::kDstIn;` 模拟了 `mask-mode: alpha` 或类似的遮罩行为。
* **`mix-blend-mode` (CSS):**  测试了不同的混合模式，包括标准的 `src_over` 和非标准的 `xor`，这直接对应于 CSS 的 `mix-blend-mode` 属性。
    * **例子：** `masking_state.blend_mode = SkBlendMode::kXor;` 模拟了设置了 `mix-blend-mode: difference` (在Skia中 `kXor` 更接近 `difference`) 的元素。
* **`clip-path` (CSS):**  测试了裁剪操作，包括简单的矩形裁剪和圆角矩形裁剪，这与 CSS 的 `clip-path` 属性相关。
    * **例子：** `CreateClip(c0(), t0(), FloatRoundedRect(100, 100, 300, 200));` 模拟了使用 `clip-path: inset(100px 100px 300px 200px round ...);` 或 `clip-path: border-radius: ...;` 的效果。
* **`transform` (CSS):**  测试了变换对合成裁剪的影响，这与 CSS 的 `transform` 属性相关。
    * **例子：** `CreateTransform(t0(), MakeRotationMatrix(45), ...)` 模拟了应用了旋转变换的元素。
* **`will-change` (CSS):**  通过 `CompositingReason::kWillChangeOpacity` 等参数，间接测试了 `will-change` 属性对图层合成的影响。

虽然 JavaScript 不直接出现在代码中，但 JavaScript 可以动态地修改 HTML 元素的 CSS 属性，从而间接地影响 `PaintArtifactCompositor` 的行为。例如，JavaScript 动画会改变元素的 `opacity` 或 `transform` 属性，而这些变化会触发重新绘制和重新合成。

**逻辑推理的假设输入与输出：**

以下是一个关于合成遮罩的逻辑推理示例：

**假设输入：**

1. 一个包含一个矩形绘制指令的 `PaintArtifact`。
2. 一个应用了 `will-change: opacity` 属性的遮罩效果节点，混合模式为 `DstIn`。
3. 遮罩效果节点包含一个白色的矩形绘制指令。

**逻辑推理：** `PaintArtifactCompositor` 会识别到遮罩需要合成（因为 `will-change: opacity`），并且混合模式为 `DstIn`，这意味着只有与遮罩重叠的部分会被保留。

**预期输出：**

1. 创建两个 `cc::Layer`：一个用于被遮罩的内容，一个用于遮罩本身。
2. 遮罩图层的混合模式设置为 `SkBlendMode::kDstIn`。
3. 父图层会有一个渲染表面来定义遮罩的范围。
4. 如果遮罩只有一个子元素，则遮罩组不需要渲染表面；如果有多个子元素，则需要渲染表面。

**用户或编程常见的使用错误举例：**

* **过度使用 `will-change` 导致不必要的图层合成：** 开发者可能会不必要地为很多元素设置 `will-change`，期望提高性能，但实际上会导致创建过多的合成图层，增加内存消耗和合成开销。
    * **例子：**  为一个静态元素设置 `will-change: transform;` 而该元素实际上没有任何动画或变换。
* **不理解混合模式对合成的影响：** 开发者可能使用了需要合成的混合模式（如 `difference` 或 `exclusion`），但没有意识到这会导致额外的合成图层创建，影响性能。
    * **例子：**  为一个包含多个元素的容器设置了 `mix-blend-mode: difference;`，而没有考虑性能影响。
* **错误地假设非合成遮罩的行为：**  开发者可能期望非合成遮罩像合成遮罩一样工作，但非合成遮罩不会创建单独的图层，而是直接应用到被遮罩的元素上，可能会影响其透明度等属性。
* **在需要合成裁剪的情况下使用了不支持合成裁剪的变换：** 开发者可能使用了非轴对齐的变换（例如任意角度的旋转）并期望获得合成裁剪的性能优势，但实际上 `PaintArtifactCompositor` 会回退到使用遮罩图层。

总而言之，这部分测试着重于 `PaintArtifactCompositor` 在处理各种涉及遮罩、混合模式和图层合成的复杂场景时的正确性，确保 Blink 引擎能够按照 CSS 规范和预期高效地渲染网页内容。

Prompt: 
```
这是目录为blink/renderer/platform/graphics/compositing/paint_artifact_compositor_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第4部分，共7部分，请归纳一下它的功能

"""
100), layer->ScreenSpaceTransform());
  EXPECT_EQ(gfx::Size(200, 200), layer->bounds());
  const cc::EffectNode* masked_group =
      GetPropertyTrees().effect_tree().Node(layer->effect_tree_index());
  EXPECT_FALSE(masked_group->HasRenderSurface());
  EXPECT_EQ(SkBlendMode::kSrcOver, masked_group->blend_mode);
  EXPECT_TRUE(masked_group->filters.IsEmpty());
  // It's the last effect node. |masking| has been decomposited.
  EXPECT_EQ(masked_group, GetPropertyTrees().effect_tree().back());
}

TEST_P(PaintArtifactCompositorTest, CompositedMaskOneChild) {
  auto* masked =
      CreateOpacityEffect(e0(), 1.0, CompositingReason::kWillChangeOpacity);
  EffectPaintPropertyNode::State masking_state;
  masking_state.local_transform_space = &t0();
  masking_state.output_clip = &c0();
  masking_state.blend_mode = SkBlendMode::kDstIn;
  masking_state.direct_compositing_reasons =
      CompositingReason::kWillChangeOpacity;
  auto* masking =
      EffectPaintPropertyNode::Create(*masked, std::move(masking_state));

  TestPaintArtifact artifact;
  artifact.Chunk(t0(), c0(), *masked)
      .RectDrawing(gfx::Rect(100, 100, 200, 200), Color::kGray)
      .RectKnownToBeOpaque(gfx::Rect(100, 100, 200, 200))
      .HasText()
      .TextKnownToBeOnOpaqueBackground();
  artifact.Chunk(t0(), c0(), *masking)
      .RectDrawing(gfx::Rect(150, 150, 100, 100), Color::kWhite);
  Update(artifact.Build());
  ASSERT_EQ(2u, LayerCount());

  // Composited mask doesn't affect opaqueness of the masked layer.
  const cc::Layer* masked_layer = LayerAt(0);
  EXPECT_TRUE(masked_layer->contents_opaque());
  EXPECT_TRUE(masked_layer->contents_opaque_for_text());

  const cc::Layer* masking_layer = LayerAt(1);
  const cc::EffectNode* masking_group =
      GetPropertyTrees().effect_tree().Node(masking_layer->effect_tree_index());

  // Render surface is not needed for one child.
  EXPECT_FALSE(masking_group->HasRenderSurface());
  EXPECT_EQ(SkBlendMode::kDstIn, masking_group->blend_mode);

  // The parent also has a render surface to define the scope of the backdrop
  // of the kDstIn blend mode.
  EXPECT_TRUE(GetPropertyTrees()
                  .effect_tree()
                  .parent(masking_group)
                  ->HasRenderSurface());
}

TEST_P(PaintArtifactCompositorTest, NonCompositedMaskClearsOpaqueness) {
  auto* masked =
      CreateOpacityEffect(e0(), 1.0, CompositingReason::kWillChangeOpacity);
  EffectPaintPropertyNode::State masking_state;
  masking_state.local_transform_space = &t0();
  masking_state.output_clip = &c0();
  masking_state.blend_mode = SkBlendMode::kDstIn;
  auto* masking =
      EffectPaintPropertyNode::Create(*masked, std::move(masking_state));

  TestPaintArtifact artifact;
  artifact.Chunk(t0(), c0(), *masked)
      .RectDrawing(gfx::Rect(100, 100, 200, 200), Color::kGray)
      .RectKnownToBeOpaque(gfx::Rect(100, 100, 200, 200))
      .HasText()
      .TextKnownToBeOnOpaqueBackground();
  artifact.Chunk(t0(), c0(), *masking)
      .RectDrawing(gfx::Rect(150, 150, 100, 100), Color::kWhite);
  Update(artifact.Build());
  ASSERT_EQ(1u, LayerCount());

  // Non-composited mask clears opaqueness status of the masked layer.
  const cc::Layer* layer = LayerAt(0);
  EXPECT_EQ(gfx::Size(200, 200), layer->bounds());
  EXPECT_FALSE(layer->contents_opaque());
  EXPECT_FALSE(layer->contents_opaque_for_text());
}

TEST_P(PaintArtifactCompositorTest, CompositedMaskTwoChildren) {
  auto* masked =
      CreateOpacityEffect(e0(), 1.0, CompositingReason::kWillChangeOpacity);
  EffectPaintPropertyNode::State masking_state;
  masking_state.local_transform_space = &t0();
  masking_state.output_clip = &c0();
  masking_state.blend_mode = SkBlendMode::kDstIn;
  auto* masking =
      EffectPaintPropertyNode::Create(*masked, std::move(masking_state));

  auto* child_of_masked =
      CreateOpacityEffect(*masking, 1.0, CompositingReason::kWillChangeOpacity);

  TestPaintArtifact artifact;
  artifact.Chunk(t0(), c0(), *masked)
      .RectDrawing(gfx::Rect(100, 100, 200, 200), Color::kGray);
  artifact.Chunk(t0(), c0(), *child_of_masked)
      .RectDrawing(gfx::Rect(100, 100, 200, 200), Color::kGray);
  artifact.Chunk(t0(), c0(), *masking)
      .RectDrawing(gfx::Rect(150, 150, 100, 100), Color::kWhite);
  Update(artifact.Build());
  ASSERT_EQ(3u, LayerCount());

  const cc::Layer* masking_layer = LayerAt(2);
  const cc::EffectNode* masking_group =
      GetPropertyTrees().effect_tree().Node(masking_layer->effect_tree_index());

  // There is a render surface because there are two children.
  EXPECT_TRUE(masking_group->HasRenderSurface());
  EXPECT_EQ(SkBlendMode::kDstIn, masking_group->blend_mode);

  // The parent also has a render surface to define the scope of the backdrop
  // of the kDstIn blend mode.
  EXPECT_TRUE(GetPropertyTrees()
                  .effect_tree()
                  .parent(masking_group)
                  ->HasRenderSurface());
}

TEST_P(PaintArtifactCompositorTest, NonCompositedSimpleExoticBlendMode) {
  auto* masked =
      CreateOpacityEffect(e0(), 1.0, CompositingReason::kWillChangeOpacity);
  EffectPaintPropertyNode::State masking_state;
  masking_state.local_transform_space = &t0();
  masking_state.output_clip = &c0();
  masking_state.blend_mode = SkBlendMode::kXor;
  auto* masking =
      EffectPaintPropertyNode::Create(*masked, std::move(masking_state));

  TestPaintArtifact artifact;
  artifact.Chunk(t0(), c0(), *masked)
      .RectDrawing(gfx::Rect(100, 100, 200, 200), Color::kGray);
  artifact.Chunk(t0(), c0(), *masking)
      .RectDrawing(gfx::Rect(150, 150, 100, 100), Color::kWhite);
  Update(artifact.Build());
  ASSERT_EQ(1u, LayerCount());

  const cc::Layer* layer = LayerAt(0);
  const cc::EffectNode* group =
      GetPropertyTrees().effect_tree().Node(layer->effect_tree_index());
  EXPECT_FALSE(group->HasRenderSurface());
  EXPECT_EQ(SkBlendMode::kSrcOver, group->blend_mode);
  // It's the last effect node. |masking| has been decomposited.
  EXPECT_EQ(group, GetPropertyTrees().effect_tree().back());
}

TEST_P(PaintArtifactCompositorTest, ForcedCompositedExoticBlendMode) {
  auto* masked =
      CreateOpacityEffect(e0(), 1.0, CompositingReason::kWillChangeOpacity);
  EffectPaintPropertyNode::State masking_state;
  masking_state.local_transform_space = &t0();
  masking_state.output_clip = &c0();
  masking_state.blend_mode = SkBlendMode::kXor;
  masking_state.direct_compositing_reasons = CompositingReason::kOverlap;
  auto* masking =
      EffectPaintPropertyNode::Create(*masked, std::move(masking_state));

  TestPaintArtifact artifact;
  artifact.Chunk(t0(), c0(), *masked)
      .RectDrawing(gfx::Rect(100, 100, 200, 200), Color::kGray);
  artifact.Chunk(t0(), c0(), *masking)
      .RectDrawing(gfx::Rect(150, 150, 100, 100), Color::kWhite);
  Update(artifact.Build());
  ASSERT_EQ(2u, LayerCount());

  const cc::Layer* masking_layer = LayerAt(1);
  const cc::EffectNode* masking_group =
      GetPropertyTrees().effect_tree().Node(masking_layer->effect_tree_index());
  EXPECT_EQ(SkBlendMode::kXor, masking_group->blend_mode);

  // This requires a render surface.
  EXPECT_TRUE(masking_group->HasRenderSurface());
  // The parent also requires a render surface to define the backdrop scope of
  // the blend mode.
  EXPECT_TRUE(GetPropertyTrees()
                  .effect_tree()
                  .parent(masking_group)
                  ->HasRenderSurface());
}

TEST_P(PaintArtifactCompositorTest,
       CompositedExoticBlendModeOnTwoOpacityAnimationLayers) {
  auto* masked =
      CreateOpacityEffect(e0(), 1.0, CompositingReason::kWillChangeOpacity);
  auto* masked_child1 = CreateOpacityEffect(
      *masked, 1.0, CompositingReason::kActiveOpacityAnimation);
  auto* masked_child2 = CreateOpacityEffect(
      *masked, 1.0, CompositingReason::kActiveOpacityAnimation);
  EffectPaintPropertyNode::State masking_state;
  masking_state.local_transform_space = &t0();
  masking_state.output_clip = &c0();
  masking_state.blend_mode = SkBlendMode::kXor;
  auto* masking =
      EffectPaintPropertyNode::Create(*masked, std::move(masking_state));

  TestPaintArtifact artifact;
  artifact.Chunk(t0(), c0(), *masked_child1)
      .RectDrawing(gfx::Rect(100, 100, 200, 200), Color::kGray);
  artifact.Chunk(t0(), c0(), *masked_child2)
      .RectDrawing(gfx::Rect(100, 100, 200, 200), Color::kBlack);
  artifact.Chunk(t0(), c0(), *masking)
      .RectDrawing(gfx::Rect(150, 150, 100, 100), Color::kWhite);
  Update(artifact.Build());
  ASSERT_EQ(3u, LayerCount());

  const cc::Layer* masking_layer = LayerAt(2);
  const cc::EffectNode* masking_group =
      GetPropertyTrees().effect_tree().Node(masking_layer->effect_tree_index());
  EXPECT_EQ(SkBlendMode::kXor, masking_group->blend_mode);

  // This requires a render surface.
  EXPECT_TRUE(masking_group->HasRenderSurface());
  // The parent also requires a render surface to define the backdrop scope of
  // the blend mode.
  EXPECT_TRUE(GetPropertyTrees()
                  .effect_tree()
                  .parent(masking_group)
                  ->HasRenderSurface());
}

TEST_P(PaintArtifactCompositorTest,
       CompositedExoticBlendModeOnTwo3DTransformLayers) {
  auto* masked =
      CreateOpacityEffect(e0(), 1.0, CompositingReason::kWillChangeOpacity);
  auto* transform1 = CreateTransform(t0(), gfx::Transform(), gfx::Point3F(),
                                     CompositingReason::k3DTransform);
  auto* transform2 = CreateTransform(t0(), gfx::Transform(), gfx::Point3F(),
                                     CompositingReason::k3DTransform);
  EffectPaintPropertyNode::State masking_state;
  masking_state.local_transform_space = &t0();
  masking_state.output_clip = &c0();
  masking_state.blend_mode = SkBlendMode::kXor;
  auto* masking =
      EffectPaintPropertyNode::Create(*masked, std::move(masking_state));

  TestPaintArtifact artifact;
  artifact.Chunk(*transform1, c0(), *masked)
      .RectDrawing(gfx::Rect(100, 100, 200, 200), Color::kGray);
  artifact.Chunk(*transform2, c0(), *masked)
      .RectDrawing(gfx::Rect(100, 100, 200, 200), Color::kBlack);
  artifact.Chunk(t0(), c0(), *masking)
      .RectDrawing(gfx::Rect(150, 150, 100, 100), Color::kWhite);
  Update(artifact.Build());
  ASSERT_EQ(3u, LayerCount());

  const cc::Layer* masking_layer = LayerAt(2);
  const cc::EffectNode* masking_group =
      GetPropertyTrees().effect_tree().Node(masking_layer->effect_tree_index());
  EXPECT_EQ(SkBlendMode::kXor, masking_group->blend_mode);

  // This requires a render surface.
  EXPECT_TRUE(masking_group->HasRenderSurface());
  // The parent also requires a render surface to define the backdrop scope of
  // the blend mode.
  EXPECT_TRUE(GetPropertyTrees()
                  .effect_tree()
                  .parent(masking_group)
                  ->HasRenderSurface());
}

TEST_P(PaintArtifactCompositorTest, DecompositeExoticBlendModeWithoutBackdrop) {
  auto* parent_effect =
      CreateOpacityEffect(e0(), 1.0, CompositingReason::kWillChangeOpacity);
  EffectPaintPropertyNode::State blend_state1;
  blend_state1.local_transform_space = &t0();
  blend_state1.blend_mode = SkBlendMode::kScreen;
  auto* blend_effect1 =
      EffectPaintPropertyNode::Create(*parent_effect, std::move(blend_state1));
  EffectPaintPropertyNode::State blend_state2;
  blend_state2.local_transform_space = &t0();
  blend_state2.blend_mode = SkBlendMode::kScreen;
  auto* blend_effect2 =
      EffectPaintPropertyNode::Create(*parent_effect, std::move(blend_state2));

  Update(TestPaintArtifact()
             .Chunk(t0(), c0(), *blend_effect1)
             .RectDrawing(gfx::Rect(100, 100, 200, 200), Color::kGray)
             .Chunk(t0(), c0(), *blend_effect2)
             .RectDrawing(gfx::Rect(100, 100, 200, 200), Color::kBlack)
             .Build());

  ASSERT_EQ(1u, LayerCount());
  const auto* effect =
      GetPropertyTrees().effect_tree().Node(LayerAt(0)->effect_tree_index());
  EXPECT_EQ(1.0f, effect->opacity);
  EXPECT_EQ(SkBlendMode::kSrcOver, effect->blend_mode);
  // Don't need a render surface because all blend effects are decomposited.
  EXPECT_FALSE(effect->HasRenderSurface());
}

TEST_P(PaintArtifactCompositorTest,
       DecompositeExoticBlendModeWithNonDrawingLayer) {
  auto* parent_effect =
      CreateOpacityEffect(e0(), 1.0, CompositingReason::kWillChangeOpacity);
  EffectPaintPropertyNode::State blend_state1;
  blend_state1.local_transform_space = &t0();
  blend_state1.blend_mode = SkBlendMode::kScreen;
  auto* blend_effect1 =
      EffectPaintPropertyNode::Create(*parent_effect, std::move(blend_state1));
  EffectPaintPropertyNode::State blend_state2;
  blend_state2.local_transform_space = &t0();
  blend_state2.blend_mode = SkBlendMode::kScreen;
  auto* blend_effect2 =
      EffectPaintPropertyNode::Create(*parent_effect, std::move(blend_state2));
  auto* transform = CreateAnimatingTransform(t0());

  Update(TestPaintArtifact()
             .Chunk(*transform, c0(), *parent_effect)
             .Bounds(gfx::Rect(0, 0, 33, 44))
             .Chunk(t0(), c0(), *blend_effect1)
             .RectDrawing(gfx::Rect(100, 100, 200, 200), Color::kGray)
             .Chunk(t0(), c0(), *blend_effect2)
             .RectDrawing(gfx::Rect(200, 200, 200, 200), Color::kBlack)
             .Build());

  ASSERT_EQ(2u, LayerCount());
  // This is the empty layer forced by |transform|.
  EXPECT_EQ(gfx::Size(33, 44), LayerAt(0)->bounds());
  EXPECT_FALSE(LayerAt(0)->draws_content());
  // This is the layer containing the paint chunks with |blend_effect1| and
  // |blend_effect2| decomposited.
  EXPECT_EQ(gfx::Size(300, 300), LayerAt(1)->bounds());
  const auto* effect =
      GetPropertyTrees().effect_tree().Node(LayerAt(1)->effect_tree_index());
  EXPECT_EQ(1.0f, effect->opacity);
  EXPECT_EQ(SkBlendMode::kSrcOver, effect->blend_mode);
  // Don't need a render surface because all blend effects are decomposited.
  EXPECT_FALSE(effect->HasRenderSurface());
}

TEST_P(PaintArtifactCompositorTest, UpdateProducesNewSequenceNumber) {
  // A 90 degree clockwise rotation about (100, 100).
  auto* transform =
      CreateTransform(t0(), MakeRotationMatrix(90), gfx::Point3F(100, 100, 0),
                      CompositingReason::k3DTransform);
  auto* clip = CreateClip(c0(), t0(), FloatRoundedRect(100, 100, 300, 200));
  auto* effect = CreateOpacityEffect(e0(), 0.5);

  TestPaintArtifact test_artifact;
  test_artifact.Chunk(*transform, *clip, *effect)
      .RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kWhite);
  test_artifact.Chunk().RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kGray);
  auto& artifact = test_artifact.Build();

  Update(artifact);

  // Two content layers for the differentiated rect drawings and three dummy
  // layers for each of the transform, clip and effect nodes.
  EXPECT_EQ(2u, RootLayer()->children().size());
  int sequence_number = GetPropertyTrees().sequence_number();
  EXPECT_GT(sequence_number, 0);
  for (auto layer : RootLayer()->children()) {
    EXPECT_EQ(sequence_number, layer->property_tree_sequence_number());
  }

  Update(artifact);

  EXPECT_EQ(2u, RootLayer()->children().size());
  sequence_number++;
  EXPECT_EQ(sequence_number, GetPropertyTrees().sequence_number());
  for (auto layer : RootLayer()->children()) {
    EXPECT_EQ(sequence_number, layer->property_tree_sequence_number());
  }

  Update(artifact);

  EXPECT_EQ(2u, RootLayer()->children().size());
  sequence_number++;
  EXPECT_EQ(sequence_number, GetPropertyTrees().sequence_number());
  for (auto layer : RootLayer()->children()) {
    EXPECT_EQ(sequence_number, layer->property_tree_sequence_number());
  }
}

TEST_P(PaintArtifactCompositorTest, DecompositeClip) {
  // A clipped paint chunk that gets merged into a previous layer should
  // only contribute clipped bounds to the layer bound.
  auto* clip = CreateClip(c0(), t0(), FloatRoundedRect(75, 75, 100, 100));

  TestPaintArtifact artifact;
  artifact.Chunk().RectDrawing(gfx::Rect(50, 50, 100, 100), Color::kGray);
  artifact.Chunk(t0(), *clip, e0())
      .RectDrawing(gfx::Rect(100, 100, 100, 100), Color::kGray);
  Update(artifact.Build());
  ASSERT_EQ(1u, LayerCount());

  const cc::Layer* layer = LayerAt(0);
  EXPECT_EQ(gfx::Vector2dF(50.f, 50.f), layer->offset_to_transform_parent());
  EXPECT_EQ(gfx::Size(125, 125), layer->bounds());
}

TEST_P(PaintArtifactCompositorTest, DecompositeEffect) {
  // An effect node without direct compositing reason and does not need to
  // group compositing descendants should not be composited and can merge
  // with other chunks.

  auto* effect = CreateOpacityEffect(e0(), 0.5);

  TestPaintArtifact artifact;
  artifact.Chunk().RectDrawing(gfx::Rect(50, 25, 100, 100), Color::kGray);
  artifact.Chunk(t0(), c0(), *effect)
      .RectDrawing(gfx::Rect(25, 75, 100, 100), Color::kGray);
  artifact.Chunk().RectDrawing(gfx::Rect(75, 75, 100, 100), Color::kGray);
  Update(artifact.Build());
  ASSERT_EQ(1u, LayerCount());

  const cc::Layer* layer = LayerAt(0);
  EXPECT_EQ(gfx::Vector2dF(25.f, 25.f), layer->offset_to_transform_parent());
  EXPECT_EQ(gfx::Size(150, 150), layer->bounds());
  EXPECT_EQ(1, layer->effect_tree_index());
}

TEST_P(PaintArtifactCompositorTest, DirectlyCompositedEffect) {
  // An effect node with direct compositing shall be composited.
  auto* effect = CreateOpacityEffect(e0(), 0.5f, CompositingReason::kAll);

  TestPaintArtifact artifact;
  artifact.Chunk().RectDrawing(gfx::Rect(50, 25, 100, 100), Color::kGray);
  artifact.Chunk(t0(), c0(), *effect)
      .RectDrawing(gfx::Rect(25, 75, 100, 100), Color::kGray);
  artifact.Chunk().RectDrawing(gfx::Rect(75, 75, 100, 100), Color::kGray);
  Update(artifact.Build());
  ASSERT_EQ(3u, LayerCount());

  const cc::Layer* layer1 = LayerAt(0);
  EXPECT_EQ(gfx::Vector2dF(50.f, 25.f), layer1->offset_to_transform_parent());
  EXPECT_EQ(gfx::Size(100, 100), layer1->bounds());
  EXPECT_EQ(1, layer1->effect_tree_index());

  const cc::Layer* layer2 = LayerAt(1);
  EXPECT_EQ(gfx::Vector2dF(25.f, 75.f), layer2->offset_to_transform_parent());
  EXPECT_EQ(gfx::Size(100, 100), layer2->bounds());
  const cc::EffectNode* effect_node =
      GetPropertyTrees().effect_tree().Node(layer2->effect_tree_index());
  EXPECT_EQ(1, effect_node->parent_id);
  EXPECT_EQ(0.5f, effect_node->opacity);

  const cc::Layer* layer3 = LayerAt(2);
  EXPECT_EQ(gfx::Vector2dF(75.f, 75.f), layer3->offset_to_transform_parent());
  EXPECT_EQ(gfx::Size(100, 100), layer3->bounds());
  EXPECT_EQ(1, layer3->effect_tree_index());
}

TEST_P(PaintArtifactCompositorTest, DecompositeDeepEffect) {
  // A paint chunk may enter multiple level effects with or without compositing
  // reasons. This test verifies we still decomposite effects without a direct
  // reason, but stop at a directly composited effect.
  auto* effect1 = CreateOpacityEffect(e0(), 0.1f);
  auto* effect2 = CreateOpacityEffect(*effect1, 0.2f, CompositingReason::kAll);
  auto* effect3 = CreateOpacityEffect(*effect2, 0.3f);

  TestPaintArtifact artifact;
  artifact.Chunk().RectDrawing(gfx::Rect(50, 25, 100, 100), Color::kGray);
  artifact.Chunk(t0(), c0(), *effect3)
      .RectDrawing(gfx::Rect(25, 75, 100, 100), Color::kGray);
  artifact.Chunk().RectDrawing(gfx::Rect(75, 75, 100, 100), Color::kGray);
  Update(artifact.Build());
  ASSERT_EQ(3u, LayerCount());

  const cc::Layer* layer1 = LayerAt(0);
  EXPECT_EQ(gfx::Vector2dF(50.f, 25.f), layer1->offset_to_transform_parent());
  EXPECT_EQ(gfx::Size(100, 100), layer1->bounds());
  EXPECT_EQ(1, layer1->effect_tree_index());

  const cc::Layer* layer2 = LayerAt(1);
  EXPECT_EQ(gfx::Vector2dF(25.f, 75.f), layer2->offset_to_transform_parent());
  EXPECT_EQ(gfx::Size(100, 100), layer2->bounds());
  const cc::EffectNode* effect_node2 =
      GetPropertyTrees().effect_tree().Node(layer2->effect_tree_index());
  EXPECT_EQ(0.2f, effect_node2->opacity);
  const cc::EffectNode* effect_node1 =
      GetPropertyTrees().effect_tree().Node(effect_node2->parent_id);
  EXPECT_EQ(1, effect_node1->parent_id);
  EXPECT_EQ(0.1f, effect_node1->opacity);

  const cc::Layer* layer3 = LayerAt(2);
  EXPECT_EQ(gfx::Vector2dF(75.f, 75.f), layer3->offset_to_transform_parent());
  EXPECT_EQ(gfx::Size(100, 100), layer3->bounds());
  EXPECT_EQ(1, layer3->effect_tree_index());
}

TEST_P(PaintArtifactCompositorTest, IndirectlyCompositedEffect) {
  // An effect node without direct compositing still needs to be composited
  // for grouping, if some chunks need to be composited.
  auto* effect = CreateOpacityEffect(e0(), 0.5f);
  auto* transform = CreateTransform(t0(), gfx::Transform(), gfx::Point3F(),
                                    CompositingReason::k3DTransform);

  TestPaintArtifact artifact;
  artifact.Chunk().RectDrawing(gfx::Rect(50, 25, 100, 100), Color::kGray);
  artifact.Chunk(t0(), c0(), *effect)
      .RectDrawing(gfx::Rect(25, 75, 100, 100), Color::kGray);
  artifact.Chunk(*transform, c0(), *effect)
      .RectDrawing(gfx::Rect(75, 75, 100, 100), Color::kGray);
  Update(artifact.Build());
  ASSERT_EQ(3u, LayerCount());

  const cc::Layer* layer1 = LayerAt(0);
  EXPECT_EQ(gfx::Vector2dF(50.f, 25.f), layer1->offset_to_transform_parent());
  EXPECT_EQ(gfx::Size(100, 100), layer1->bounds());
  EXPECT_EQ(1, layer1->effect_tree_index());

  const cc::Layer* layer2 = LayerAt(1);
  EXPECT_EQ(gfx::Vector2dF(25.f, 75.f), layer2->offset_to_transform_parent());
  EXPECT_EQ(gfx::Size(100, 100), layer2->bounds());
  const cc::EffectNode* effect_node =
      GetPropertyTrees().effect_tree().Node(layer2->effect_tree_index());
  EXPECT_EQ(1, effect_node->parent_id);
  EXPECT_EQ(0.5f, effect_node->opacity);

  const cc::Layer* layer3 = LayerAt(2);
  EXPECT_EQ(gfx::Vector2dF(75.f, 75.f), layer3->offset_to_transform_parent());
  EXPECT_EQ(gfx::Size(100, 100), layer3->bounds());
  EXPECT_EQ(effect_node->id, layer3->effect_tree_index());
}

TEST_P(PaintArtifactCompositorTest, DecompositedEffectNotMergingDueToOverlap) {
  // This tests an effect that doesn't need to be composited, but needs
  // separate backing due to overlap with a previous composited effect.
  auto* effect1 = CreateOpacityEffect(e0(), 0.1f);
  auto* effect2 = CreateOpacityEffect(e0(), 0.2f);
  auto* transform = CreateTransform(t0(), gfx::Transform(), gfx::Point3F(),
                                    CompositingReason::k3DTransform);
  TestPaintArtifact artifact;
  artifact.Chunk().RectDrawing(gfx::Rect(0, 0, 40, 40), Color::kGray);
  artifact.Chunk(t0(), c0(), *effect1)
      .RectDrawing(gfx::Rect(50, 0, 40, 40), Color::kGray);
  // This chunk has a transform that must be composited, thus causing effect1
  // to be composited too.
  artifact.Chunk(*transform, c0(), *effect1)
      .RectDrawing(gfx::Rect(100, 0, 40, 40), Color::kGray);
  artifact.Chunk(t0(), c0(), *effect2)
      .RectDrawing(gfx::Rect(100, 50, 40, 40), Color::kGray);
  // This chunk overlaps with the 2nd chunk, but is seemingly safe to merge.
  // However because effect1 gets composited due to a composited transform,
  // we can't merge with effect1 nor skip it to merge with the first chunk.
  artifact.Chunk(t0(), c0(), *effect2)
      .RectDrawing(gfx::Rect(50, 0, 40, 40), Color::kGray);

  Update(artifact.Build());
  ASSERT_EQ(4u, LayerCount());

  const cc::Layer* layer1 = LayerAt(0);
  EXPECT_EQ(gfx::Vector2dF(0.f, 0.f), layer1->offset_to_transform_parent());
  EXPECT_EQ(gfx::Size(40, 40), layer1->bounds());
  EXPECT_EQ(1, layer1->effect_tree_index());

  const cc::Layer* layer2 = LayerAt(1);
  EXPECT_EQ(gfx::Vector2dF(50.f, 0.f), layer2->offset_to_transform_parent());
  EXPECT_EQ(gfx::Size(40, 40), layer2->bounds());
  const cc::EffectNode* effect_node =
      GetPropertyTrees().effect_tree().Node(layer2->effect_tree_index());
  EXPECT_EQ(1, effect_node->parent_id);
  EXPECT_EQ(0.1f, effect_node->opacity);

  const cc::Layer* layer3 = LayerAt(2);
  EXPECT_EQ(gfx::Vector2dF(100.f, 0.f), layer3->offset_to_transform_parent());
  EXPECT_EQ(gfx::Size(40, 40), layer3->bounds());
  EXPECT_EQ(effect_node->id, layer3->effect_tree_index());

  const cc::Layer* layer4 = LayerAt(3);
  EXPECT_EQ(gfx::Vector2dF(50.f, 0.f), layer4->offset_to_transform_parent());
  EXPECT_EQ(gfx::Size(90, 90), layer4->bounds());
  EXPECT_EQ(1, layer4->effect_tree_index());
}

TEST_P(PaintArtifactCompositorTest, EffectivelyInvisibleChunk) {
  UpdateWithEffectivelyInvisibleChunk(false, false);
  ASSERT_EQ(1u, LayerCount());
  EXPECT_EQ(gfx::Size(10, 10), LayerAt(0)->bounds());
  EXPECT_FALSE(LayerAt(0)->draws_content());
  EXPECT_FALSE(LayerAt(0)->GetPicture());
}

TEST_P(PaintArtifactCompositorTest, EffectivelyInvisibleSolidColorChunk) {
  TestPaintArtifact artifact;
  artifact.Chunk()
      .EffectivelyInvisible()
      .RectDrawing(gfx::Rect(10, 0, 10, 10), Color(255, 0, 0))
      .IsSolidColor();
  Update(artifact.Build());
  ASSERT_EQ(1u, LayerCount());
  EXPECT_EQ(gfx::Size(10, 10), LayerAt(0)->bounds());
  EXPECT_TRUE(LayerAt(0)->IsSolidColorLayerForTesting());
  EXPECT_FALSE(LayerAt(0)->draws_content());
  EXPECT_FALSE(LayerAt(0)->GetPicture());
}

TEST_P(PaintArtifactCompositorTest,
       EffectivelyInvisibleChunkWithPrecedingChunk) {
  UpdateWithEffectivelyInvisibleChunk(true, false);
  ASSERT_EQ(1u, LayerCount());
  EXPECT_EQ(gfx::Size(20, 10), LayerAt(0)->bounds());
  EXPECT_TRUE(LayerAt(0)->draws_content());
  EXPECT_THAT(LayerAt(0)->GetPicture(),
              Pointee(DrawsRectangles(
                  {RectWithColor(gfx::RectF(0, 0, 10, 10), Color::kBlack)})));
}

TEST_P(PaintArtifactCompositorTest,
       EffectivelyInvisibleChunkWithSubsequentChunk) {
  UpdateWithEffectivelyInvisibleChunk(false, true);
  ASSERT_EQ(1u, LayerCount());
  EXPECT_EQ(gfx::Size(20, 20), LayerAt(0)->bounds());
  EXPECT_TRUE(LayerAt(0)->draws_content());
  EXPECT_THAT(LayerAt(0)->GetPicture(),
              Pointee(DrawsRectangles(
                  {RectWithColor(gfx::RectF(0, 10, 10, 10), Color::kWhite)})));
}

TEST_P(PaintArtifactCompositorTest,
       EffectivelyInvisibleChunkWithPrecedingAndSubsequentChunks) {
  UpdateWithEffectivelyInvisibleChunk(true, true);
  ASSERT_EQ(1u, LayerCount());
  EXPECT_EQ(gfx::Size(20, 20), LayerAt(0)->bounds());
  EXPECT_TRUE(LayerAt(0)->draws_content());
  EXPECT_THAT(LayerAt(0)->GetPicture(),
              Pointee(DrawsRectangles(
                  {RectWithColor(gfx::RectF(0, 0, 10, 10), Color::kBlack),
                   RectWithColor(gfx::RectF(0, 10, 10, 10), Color::kWhite)})));
}

TEST_P(PaintArtifactCompositorTest, UpdateManagesLayerElementIds) {
  auto* transform = CreateAnimatingTransform(t0());
  CompositorElementId element_id = transform->GetCompositorElementId();

  {
    TestPaintArtifact artifact;
    artifact.Chunk(*transform, c0(), e0())
        .RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kBlack);

    Update(artifact.Build());
    ASSERT_EQ(1u, LayerCount());
    ASSERT_TRUE(GetLayerTreeHost().IsElementInPropertyTrees(
        element_id, cc::ElementListType::ACTIVE));
  }

  {
    TestPaintArtifact artifact;
    ASSERT_TRUE(GetLayerTreeHost().IsElementInPropertyTrees(
        element_id, cc::ElementListType::ACTIVE));
    Update(artifact.Build());
    ASSERT_EQ(0u, LayerCount());
    ASSERT_FALSE(GetLayerTreeHost().IsElementInPropertyTrees(
        element_id, cc::ElementListType::ACTIVE));
  }
}

TEST_P(PaintArtifactCompositorTest, SynthesizedClipSimple) {
  // This tests the simplest case that a single layer needs to be clipped
  // by a single composited rounded clip.
  FloatRoundedRect rrect(gfx::RectF(50, 50, 300, 200), 5);
  auto* c1 = CreateClip(c0(), t0(), rrect);

  TestPaintArtifact artifact;
  artifact.Chunk(t0(), *c1, e0())
      .RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kBlack);
  Update(artifact.Build());

  // Expectation in effect stack diagram:
  //       content0
  // [ mask_isolation_0 ]
  // [        e0        ]
  // One content layer.
  ASSERT_EQ(1u, LayerCount());
  // There is still a "synthesized layer" but it's null.
  ASSERT_EQ(1u, SynthesizedClipLayerCount());
  EXPECT_FALSE(SynthesizedClipLayerAt(0));

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
  EXPECT_TRUE(mask_isolation_0.is_fast_rounded_corner);
  EXPECT_EQ(gfx::RRectF(50, 50, 300, 200, 5),
            mask_isolation_0.mask_filter_info.rounded_corner_bounds());
  EXPECT_FALSE(mask_isolation_0.HasRenderSurface());
}

TEST_P(PaintArtifactCompositorTest, SynthesizedClipRotatedNotSupported) {
  // Synthesized clips are not currently supported when rotated (or any
  // transform that is not 2D axis-aligned).
  auto* transform =
      CreateTransform(t0(), MakeRotationMatrix(45), gfx::Point3F(100, 100, 0),
                      CompositingReason::k3DTransform);

  FloatRoundedRect rrect(gfx::RectF(50, 50, 300, 200), 5);
  auto* c1 = CreateClip(c0(), *transform, rrect);

  TestPaintArtifact artifact;
  artifact.Chunk(*transform, *c1, e0())
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
  EXPECT_EQ(gfx::Size(306, 206), clip_mask0->bounds());
  EXPECT_EQ(gfx::Vector2dF(47, 47), clip_mask0->offset_to_transform_parent());
  // c1 should be applied in the clip mask layer.
  EXPECT_EQ(c0_id, clip_mask0->clip_tree_index());
  int mask_effect_0_id = clip_mask0->effect_tree_index();
  const cc::EffectNode& mask_effect_0 =
      *GetPropertyTrees().effect_tree().Node(mask_effect_0_id);
  ASSERT_EQ(mask_isolation_0_id, mask_effect_0.parent_id);
  EXPECT_EQ(SkBlendMode::kDstIn, mask_effect_0.blend_mode);
  // Render surface is not needed for DstIn controlling only one layer.
  EXPECT_FALSE(mask_effect_0.HasRenderSurface());
}

TEST_P(PaintArtifactCompositorTest, SynthesizedClip90DegRotationSupported) {
  // 90-degree rotations are axis-aligned, and so the synthetic clip is
  // supported.
  auto* transform =
      CreateTransform(t0(), MakeRotationMatrix(90), gfx::Point3F(100, 100, 0),
                      CompositingReason::k3DTransform);

  FloatRoundedRect rrect(gfx::RectF(50, 50, 300, 200), 5);
  auto* c1 = CreateClip(c0(), *transform, rrect);

  TestPaintArtifact artifact;
  artifact.Chunk(*transform, *c1, e0())
      .RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kBlack);
  Update(artifact.Build());

  // Expectation in effect stack diagram:
  //       content0
  // [ mask_isolation_0 ]
  // [        e0        ]
  // One content layer.
  ASSERT_EQ(1u, LayerCount());
  // There is still a "synthesized layer" but it's null.
  ASSERT_EQ(1u, SynthesizedClipLayerCount());
  EXPECT_FALSE(SynthesizedClipLayerAt(0));

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
  EXPECT_TRUE(mask_isolation_0.is_fast_rounded_corner);
  EXPECT_EQ(gfx::RRectF(50, 50, 300, 200, 5),
            mask_isolation_0.mask_filter_info.rounded_corner_bounds());
  EXPECT_FALSE(mask_isolation_0.HasRenderSurface());
}

TEST
"""


```