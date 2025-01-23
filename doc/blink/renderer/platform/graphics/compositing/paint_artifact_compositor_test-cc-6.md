Response:
My thinking process to analyze the provided C++ test file goes like this:

1. **Understand the Purpose of Test Files:**  I know that test files in software development are designed to verify the functionality of specific code components. The name `paint_artifact_compositor_test.cc` strongly suggests this file tests the `PaintArtifactCompositor` class in Blink.

2. **Identify Key Classes/Concepts:** I scan the code for prominent class names and concepts. I see `PaintArtifact`, `PaintArtifactCompositor`, `Layer`, `PropertyTrees` (including `effect_tree`, `clip_tree`, `transform_tree`, `scroll_tree`), and concepts like compositing, render surfaces, opacity, filters, clips, transforms, and scrolling.

3. **Analyze Individual Test Cases (TEST_P):**  The `TEST_P` macro indicates parameterized tests. I go through each test function and try to understand what aspect of `PaintArtifactCompositor` it's examining. I look for:
    * **Setup:** What objects are being created (`CreateAnimatingOpacityEffect`, `CreateFilterEffect`, `CreateClip`, `CreateTransform`, etc.)? What initial state is being set up?
    * **Action:** What function of `PaintArtifactCompositor` is being called (mostly `Update`)? What is the input to this function (`TestPaintArtifact`)?
    * **Assertions/Expectations:** What are the `ASSERT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_OPACITY` calls checking?  These reveal the expected behavior.

4. **Relate to Web Concepts (JavaScript, HTML, CSS):**  As I analyze the test cases, I try to connect the tested functionalities to their corresponding concepts in web development:
    * **Opacity:**  Directly maps to the CSS `opacity` property.
    * **Filters:** Maps to CSS filter properties (e.g., `blur`).
    * **Transforms:** Maps to CSS transform properties (e.g., `rotate`, `translate`).
    * **Clips:** Maps to CSS `clip-path` or the older `clip` property, or even overflow hidden.
    * **Scrolling:** Relates to the browser's scrolling behavior and how content is rendered when it overflows.
    * **Render Surfaces:**  While not a direct CSS property, I know they are an important optimization and rendering concept in browsers, triggered by various CSS properties or browser heuristics.

5. **Infer Functionality from Tests:** By understanding what each test case checks, I can build a comprehensive list of the `PaintArtifactCompositor`'s functionalities. For example, if a test checks that a filter creates a render surface, I know the compositor is responsible for that behavior.

6. **Identify Logic and Assumptions:** I look for conditional logic within the tests (like the `ASSERT_TRUE` before the non-2D clip test) and try to understand the assumptions behind the tests. This helps identify the specific scenarios being tested.

7. **Consider User/Programming Errors:**  Based on the tested functionalities, I think about common mistakes developers might make related to these web concepts. For instance, misusing `will-change`, unexpected render surface creation, or incorrect understanding of how transforms and clips interact.

8. **Address the "Part 7 of 7" Constraint:** Since this is the final part, I focus on summarizing the overall functionality based on the analysis of all the tests. I try to give a high-level overview of what the `PaintArtifactCompositor` does within the Blink rendering pipeline.

9. **Structure the Output:** I organize my findings into logical sections (Functionality, Relationship to Web Technologies, Logic and Assumptions, Common Errors, Summary) to make the information clear and easy to understand.

**Example of Internal Monologue during analysis:**

"Okay, this test is called `OpacityCreatesRenderSurface`. It creates an `AnimatingOpacityEffect`. The `ASSERT_EQ(1u, LayerCount())` means it expects one composited layer. The `EXPECT_OPACITY` checks properties on the effect node. So, this test is verifying that animating opacity causes the creation of a separate composited layer (render surface)."

"This next one, `NestedOpacity`, is interesting. It's nesting opacity effects. It checks the `kHasRenderSurface` flag on the outermost animated opacity but `kNoRenderSurface` on the inner one. This suggests the compositor is being smart about when to create render surfaces to avoid unnecessary overhead. It seems like it only needs one render surface for the combined effect on multiple layers if the parent creates one."

"The `Non2dAxisAlignedClip` test creates a rotated clip. It asserts that a 'synthetic effect node' is created. This makes sense because a rotated clip is more complex to render and might require a separate compositing layer to handle correctly."

By repeating this kind of analysis for each test case, I can gradually piece together a comprehensive understanding of the `PaintArtifactCompositor`'s role and capabilities.
这是对 Chromium Blink 引擎源代码文件 `blink/renderer/platform/graphics/compositing/paint_artifact_compositor_test.cc` 的功能进行总结。基于你提供的代码片段，我们可以推断出该文件的主要功能是：

**核心功能：测试 `PaintArtifactCompositor` 类的行为和逻辑。**

`PaintArtifactCompositor` 负责将渲染过程中的 `PaintArtifact` 数据结构转换为 Compositor 可以理解的图层结构 (`cc::Layer`)，并管理这些图层的属性树 (Property Trees)。  这个测试文件通过创建不同的 `PaintArtifact` 场景，并断言生成的图层结构和属性树的状态是否符合预期，来验证 `PaintArtifactCompositor` 的正确性。

**具体测试的功能点 (从代码片段中推断)：**

1. **不透明度 (Opacity) 的处理:**
   - 测试当应用不透明度动画时，`PaintArtifactCompositor` 是否正确创建渲染表面 (Render Surface)。
   - 测试嵌套的不透明度效果如何影响渲染表面的创建。如果父效果已经创建了渲染表面，子效果可能不需要创建额外的渲染表面。
   - **与 JavaScript, HTML, CSS 的关系:** CSS 的 `opacity` 属性直接影响这里的不透明度效果。例如，使用 JavaScript 动态改变元素的 `opacity` 样式，或者在 CSS 中定义 `opacity` 值和过渡动画，都会触发 `PaintArtifactCompositor` 的相关逻辑。
   - **假设输入与输出:**  假设输入一个包含不透明度动画的 `PaintArtifact`，输出是生成一个带有 `kHasRenderSurface` 标记的图层。

2. **滤镜 (Filter) 的处理:**
   - 测试当应用滤镜 (如模糊) 时，`PaintArtifactCompositor` 是否会创建渲染表面。
   - 测试 `will-change: filter` 提示是否会强制创建渲染表面。
   - 测试滤镜动画是否会创建渲染表面。
   - **与 JavaScript, HTML, CSS 的关系:** CSS 的 `filter` 属性用于应用各种图像效果。例如，`filter: blur(5px)` 会触发相关测试。`will-change: filter` 提示浏览器该属性即将发生变化，可以触发不同的优化路径。
   - **假设输入与输出:**  假设输入一个包含模糊滤镜的 `PaintArtifact`，输出是生成一个带有 `kHasRenderSurface` 标记的图层。

3. **背景滤镜 (Backdrop Filter) 的处理:**
   - 测试当应用背景滤镜时，`PaintArtifactCompositor` 是否会创建渲染表面。
   - 测试 `will-change: backdrop-filter` 是否会强制创建渲染表面。
   - 测试背景滤镜动画是否会创建渲染表面。
   - **与 JavaScript, HTML, CSS 的关系:** CSS 的 `backdrop-filter` 属性允许对元素下方的区域应用滤镜。
   - **假设输入与输出:**  假设输入一个包含背景模糊滤镜的 `PaintArtifact`，输出是生成一个带有 `kHasRenderSurface` 标记的图层。

4. **裁剪 (Clip) 的处理:**
   - 测试非 2D 轴对齐的裁剪 (例如旋转后的矩形裁剪) 如何处理。预期会创建一个合成的效果节点。
   - 测试非 2D 轴对齐的圆角矩形裁剪。预期会创建蒙版层 (mask layer)。
   - 测试在已有的渲染表面下应用非 2D 轴对齐裁剪的情况。
   - **与 JavaScript, HTML, CSS 的关系:** CSS 的 `clip-path` 属性可以定义各种复杂的裁剪区域。使用 `transform: rotate()` 等属性旋转元素后，再应用裁剪，就会触发非 2D 轴对齐裁剪的逻辑。
   - **假设输入与输出:**  假设输入一个包含旋转裁剪的 `PaintArtifact`，输出是生成一个带有合成效果节点的图层。

5. **变换 (Transform) 的处理:**
   - 测试 `TransformPaintPropertyNode` 的更新和变化检测。
   - 测试 2D 和 3D 变换的变化如何影响图层的属性更新。
   - 测试当变换被分解为独立的 offset 时，图层的属性更新。
   - **与 JavaScript, HTML, CSS 的关系:** CSS 的 `transform` 属性用于对元素进行旋转、缩放、平移等操作。JavaScript 可以动态修改 `transform` 属性。
   - **假设输入与输出:**  假设输入一个 `PaintArtifact`，其中一个变换节点被更新，输出是相应的图层标记为需要更新属性。

6. **效果 (Effect) 的处理:**
   - 测试 `EffectPaintPropertyNode` 的更新和变化检测，例如不透明度的变化。
   - **与 JavaScript, HTML, CSS 的关系:** 这里的效果节点涵盖了不透明度、滤镜等影响元素视觉表现的属性。
   - **假设输入与输出:**  假设输入一个 `PaintArtifact`，其中一个效果节点的不透明度被更新，输出是相应的图层标记为需要更新属性。

7. **滚动 (Scroll) 的处理:**
   - 测试直接设置滚动偏移量 (`DirectlySetScrollOffset`) 的功能。
   - 测试当滚动偏移量没有变化时，是否会触发提交 (commit)。
   - 测试添加间接合成的滚动节点 (例如，内容不透明导致滚动容器合成)。
   - 测试添加非合成的滚动节点。
   - 测试添加主线程滚动的节点 (例如，有 `background-attachment: fixed` 的元素)。
   - 测试未绘制的非合成滚动节点。
   - 测试间接滚动命中测试的重绘。
   - **与 JavaScript, HTML, CSS 的关系:**  与页面的滚动行为密切相关。CSS 的 `overflow` 属性、JavaScript 设置 `scrollTop` 和 `scrollLeft` 属性都会触发相关逻辑。
   - **假设输入与输出:**  假设输入一个包含可滚动区域的 `PaintArtifact`，输出是生成一个对应的滚动图层和属性节点。

8. **像素移动滤镜裁剪扩展器 (Pixel Moving Filter Clip Expander) 的处理:**
   - 测试当使用像素移动滤镜时，裁剪扩展器的行为。
   - 测试合成和非合成的裁剪扩展器的场景。
   - **与 JavaScript, HTML, CSS 的关系:** 涉及到一些高级的渲染优化技术，可能与某些特定的滤镜效果或硬件加速有关。

9. **为纯色背景滤镜蒙版创建 PictureLayer:**
   - 测试对于纯色的背景滤镜蒙版，是否会创建 `PictureLayer`。
   - **与 JavaScript, HTML, CSS 的关系:** 纯色背景的优化，避免创建不必要的复杂图层。

**用户或编程常见的使用错误 (举例说明)：**

- **过度使用 `will-change`:** 虽然 `will-change` 可以提示浏览器进行优化，但过度使用可能会导致不必要的内存消耗和性能下降，例如，对所有元素都使用 `will-change: transform`。测试中验证了 `will-change` 是否会按预期创建渲染表面，这有助于理解其影响。
- **不理解渲染表面创建的条件:** 开发者可能不清楚哪些 CSS 属性或动画会导致创建新的渲染表面。例如，在一个元素上应用了不透明度动画，但没有意识到这会创建一个新的合成层，可能导致意想不到的层叠顺序或性能问题。测试用例通过断言渲染表面的创建时机，帮助开发者理解这些规则。
- **错误地假设裁剪的行为:** 开发者可能认为简单的 `clip` 或 `clip-path` 操作不会有性能影响，但非 2D 轴对齐的裁剪需要特殊处理，可能会创建额外的合成层。测试用例展示了这一点。

**逻辑推理的假设输入与输出 (更具体的例子):**

- **假设输入:** 一个 `TestPaintArtifact`，其中包含一个设置了 `opacity: 0.5` 的矩形。
- **预期输出:**  `PaintArtifactCompositor` 会创建一个 `cc::Layer`，其对应的效果属性节点 (EffectPaintPropertyNode) 的 `opacity` 值为 0.5。

- **假设输入:** 一个 `TestPaintArtifact`，其中包含一个应用了 `filter: blur(10px)` 的 div 元素。
- **预期输出:** `PaintArtifactCompositor` 会创建一个新的渲染表面 (Render Surface) 来应用这个滤镜效果，并生成相应的图层结构。

**作为第 7 部分的归纳总结：**

作为该测试系列的最后一部分，这个文件集中测试了 `PaintArtifactCompositor` 在各种复杂渲染场景下的行为，包括不透明度、滤镜、裁剪、变换和滚动等。它旨在确保 `PaintArtifactCompositor` 能够正确地将高层次的渲染描述 (`PaintArtifact`) 转换为底层 Compositor 可以理解的图层结构和属性树，这是 Chromium Blink 引擎渲染流水线中的关键环节。通过这些测试，可以保证在不同 CSS 属性和 JavaScript 操作下，最终的渲染结果是正确且高效的。

总而言之，`paint_artifact_compositor_test.cc` 是一个非常重要的测试文件，用于验证 Blink 引擎中负责将渲染信息转化为可合成图层的核心组件的正确性和健壮性。它覆盖了各种常见的和复杂的渲染场景，并与 Web 开发中使用的 HTML、CSS 和 JavaScript 功能紧密相关。

### 提示词
```
这是目录为blink/renderer/platform/graphics/compositing/paint_artifact_compositor_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第7部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
auto* opacity = CreateAnimatingOpacityEffect(e0());
  auto* child_composited_effect = CreateAnimatingOpacityEffect(*opacity);
  auto* grandchild_composited_effect =
      CreateAnimatingOpacityEffect(*child_composited_effect);

  TestPaintArtifact artifact;
  artifact.Chunk(t0(), c0(), *child_composited_effect)
      .RectDrawing(gfx::Rect(150, 150, 100, 100), Color::kWhite);
  artifact.Chunk(t0(), c0(), *grandchild_composited_effect)
      .RectDrawing(gfx::Rect(150, 150, 100, 100), Color::kGray);
  Update(artifact.Build());
  ASSERT_EQ(2u, LayerCount());

  const auto& effect_tree = GetPropertyTrees().effect_tree();
  // layer0's opacity animation needs a render surface because it affects
  // both layer0 and layer1.
  int layer0_effect_id = LayerAt(0)->effect_tree_index();
  EXPECT_OPACITY(layer0_effect_id, 1.f, kHasRenderSurface);
  // layer1's opacity animation doesn't need a render surface because it
  // affects layer1 only.
  int layer1_effect_id = LayerAt(1)->effect_tree_index();
  EXPECT_OPACITY(layer1_effect_id, 1.f, kNoRenderSurface);
  // Though |opacity| affects both layer0 and layer1, layer0's effect has
  // render surface, so |opacity| doesn't need a render surface.
  int opacity_id = effect_tree.Node(layer0_effect_id)->parent_id;
  EXPECT_OPACITY(opacity_id, 1.f, kNoRenderSurface);
}

TEST_P(PaintArtifactCompositorTest, FilterCreatesRenderSurface) {
  CompositorFilterOperations filter;
  filter.AppendBlurFilter(5);
  auto* e1 = CreateFilterEffect(e0(), filter,
                                CompositingReason::kActiveFilterAnimation);
  Update(TestPaintArtifact()
             .Chunk(t0(), c0(), *e1)
             .RectDrawing(gfx::Rect(150, 150, 100, 100), Color::kWhite)
             .Build());
  ASSERT_EQ(1u, LayerCount());
  EXPECT_OPACITY(LayerAt(0)->effect_tree_index(), 1.f, kHasRenderSurface);
}

TEST_P(PaintArtifactCompositorTest, WillChangeFilterCreatesRenderSurface) {
  auto* e1 = CreateFilterEffect(e0(), CompositorFilterOperations(),
                                CompositingReason::kWillChangeFilter);
  Update(TestPaintArtifact()
             .Chunk(t0(), c0(), *e1)
             .RectDrawing(gfx::Rect(150, 150, 100, 100), Color::kWhite)
             .Build());
  ASSERT_EQ(1u, LayerCount());
  EXPECT_OPACITY(LayerAt(0)->effect_tree_index(), 1.f, kHasRenderSurface);
}

TEST_P(PaintArtifactCompositorTest, FilterAnimationCreatesRenderSurface) {
  auto* e1 = CreateAnimatingFilterEffect(e0());
  Update(TestPaintArtifact()
             .Chunk(t0(), c0(), *e1)
             .RectDrawing(gfx::Rect(150, 150, 100, 100), Color::kWhite)
             .Build());
  ASSERT_EQ(1u, LayerCount());
  EXPECT_OPACITY(LayerAt(0)->effect_tree_index(), 1.f, kHasRenderSurface);
}

TEST_P(PaintArtifactCompositorTest, BackdropFilterCreatesRenderSurface) {
  CompositorFilterOperations filter;
  filter.AppendBlurFilter(5);
  auto* e1 = CreateBackdropFilterEffect(e0(), filter);
  Update(TestPaintArtifact()
             .Chunk(t0(), c0(), *e1)
             .RectDrawing(gfx::Rect(150, 150, 100, 100), Color::kWhite)
             .Build());
  ASSERT_EQ(1u, LayerCount());
  EXPECT_OPACITY(LayerAt(0)->effect_tree_index(), 1.f, kHasRenderSurface);
}

TEST_P(PaintArtifactCompositorTest,
       WillChangeBackdropFilterCreatesRenderSurface) {
  auto* e1 =
      CreateBackdropFilterEffect(e0(), CompositorFilterOperations(),
                                 CompositingReason::kWillChangeBackdropFilter);
  Update(TestPaintArtifact()
             .Chunk(t0(), c0(), *e1)
             .RectDrawing(gfx::Rect(150, 150, 100, 100), Color::kWhite)
             .Build());
  ASSERT_EQ(1u, LayerCount());
  EXPECT_OPACITY(LayerAt(0)->effect_tree_index(), 1.f, kHasRenderSurface);
}

TEST_P(PaintArtifactCompositorTest,
       BackdropFilterAnimationCreatesRenderSurface) {
  auto* e1 = CreateAnimatingBackdropFilterEffect(e0());
  Update(TestPaintArtifact()
             .Chunk(t0(), c0(), *e1)
             .RectDrawing(gfx::Rect(150, 150, 100, 100), Color::kWhite)
             .Build());
  ASSERT_EQ(1u, LayerCount());
  EXPECT_OPACITY(LayerAt(0)->effect_tree_index(), 1.f, kHasRenderSurface);
}

TEST_P(PaintArtifactCompositorTest, Non2dAxisAlignedClip) {
  auto* rotate = CreateTransform(t0(), MakeRotationMatrix(45));
  auto* clip = CreateClip(c0(), *rotate, FloatRoundedRect(50, 50, 50, 50));
  auto* opacity = CreateOpacityEffect(
      e0(), 0.5f, CompositingReason::kActiveOpacityAnimation);

  TestPaintArtifact artifact;
  artifact.Chunk(t0(), *clip, *opacity)
      .RectDrawing(gfx::Rect(50, 50, 50, 50), Color::kWhite);
  Update(artifact.Build());
  ASSERT_EQ(1u, LayerCount());

  // We should create a synthetic effect node for the non-2d-axis-aligned clip.
  int clip_id = LayerAt(0)->clip_tree_index();
  const auto* cc_clip = GetPropertyTrees().clip_tree().Node(clip_id);
  int effect_id = LayerAt(0)->effect_tree_index();
  const auto* cc_effect = GetPropertyTrees().effect_tree().Node(effect_id);
  EXPECT_OPACITY(effect_id, 1.f, kHasRenderSurface);
  EXPECT_OPACITY(cc_effect->parent_id, 0.5f, kNoRenderSurface);
  EXPECT_EQ(cc_effect->clip_id, cc_clip->parent_id);
}

TEST_P(PaintArtifactCompositorTest, Non2dAxisAlignedRoundedRectClip) {
  auto* rotate = CreateTransform(t0(), MakeRotationMatrix(45));
  FloatRoundedRect rounded_clip(gfx::RectF(50, 50, 50, 50), 5);
  auto* clip = CreateClip(c0(), *rotate, rounded_clip);
  auto* opacity = CreateOpacityEffect(
      e0(), 0.5f, CompositingReason::kActiveOpacityAnimation);

  TestPaintArtifact artifact;
  artifact.Chunk(t0(), *clip, *opacity)
      .RectDrawing(gfx::Rect(50, 50, 50, 50), Color::kWhite);
  Update(artifact.Build());
  ASSERT_EQ(2u, LayerCount());

  // We should create a synthetic effect node for the non-2d-axis-aligned clip.
  auto* masked_layer = LayerAt(0);
  EXPECT_TRUE(masked_layer->draws_content());
  int clip_id = masked_layer->clip_tree_index();
  const auto* cc_clip = GetPropertyTrees().clip_tree().Node(clip_id);
  int effect_id = masked_layer->effect_tree_index();
  const auto* cc_effect = GetPropertyTrees().effect_tree().Node(effect_id);
  EXPECT_OPACITY(effect_id, 1.f, kHasRenderSurface);
  EXPECT_OPACITY(cc_effect->parent_id, 0.5f, kNoRenderSurface);
  // cc_clip should be applied in the clip mask layer.
  EXPECT_EQ(cc_effect->clip_id, cc_clip->parent_id);

  // The mask layer is needed because the masked layer draws content.
  auto* mask_layer = LayerAt(1);
  const auto* cc_mask =
      GetPropertyTrees().effect_tree().Node(mask_layer->effect_tree_index());
  EXPECT_EQ(SkBlendMode::kDstIn, cc_mask->blend_mode);
}

TEST_P(PaintArtifactCompositorTest,
       Non2dAxisAlignedClipUnderLaterRenderSurface) {
  auto* rotate1 = CreateTransform(t0(), MakeRotationMatrix(45), gfx::Point3F(),
                                  CompositingReason::k3DTransform);
  auto* rotate2 =
      CreateTransform(*rotate1, MakeRotationMatrix(-45), gfx::Point3F(),
                      CompositingReason::k3DTransform);
  auto* clip = CreateClip(c0(), *rotate2, FloatRoundedRect(50, 50, 50, 50));
  auto* opacity = CreateOpacityEffect(
      e0(), *rotate1, &c0(), 0.5f, CompositingReason::kActiveOpacityAnimation);

  // This assert ensures the test actually tests the situation. If it fails
  // due to floating-point errors, we should choose other transformation values
  // to make it succeed.
  ASSERT_TRUE(GeometryMapper::SourceToDestinationProjection(t0(), *rotate2)
                  .Preserves2dAxisAlignment());

  TestPaintArtifact artifact;
  artifact.Chunk(t0(), c0(), *opacity)
      .RectDrawing(gfx::Rect(50, 50, 50, 50), Color::kWhite);
  artifact.Chunk(*rotate1, c0(), *opacity)
      .RectDrawing(gfx::Rect(50, 50, 50, 50), Color::kWhite);
  artifact.Chunk(*rotate2, *clip, *opacity)
      .RectDrawing(gfx::Rect(50, 50, 50, 50), Color::kWhite);
  Update(artifact.Build());
  ASSERT_EQ(3u, LayerCount());

  // We should create a synthetic effect node for the non-2d-axis-aligned clip,
  // though the accumulated transform to the known render surface was identity
  // when the cc clip node was created.
  int clip_id = LayerAt(2)->clip_tree_index();
  const auto* cc_clip = GetPropertyTrees().clip_tree().Node(clip_id);
  int effect_id = LayerAt(2)->effect_tree_index();
  const auto* cc_effect = GetPropertyTrees().effect_tree().Node(effect_id);
  EXPECT_OPACITY(effect_id, 1.f, kHasRenderSurface);
  EXPECT_OPACITY(cc_effect->parent_id, 0.5f, kHasRenderSurface);
  EXPECT_EQ(cc_effect->clip_id, cc_clip->parent_id);
}

static TransformPaintPropertyNode::State Transform3dState(
    const gfx::Transform& transform) {
  TransformPaintPropertyNode::State state{{transform}};
  state.direct_compositing_reasons = CompositingReason::k3DTransform;
  return state;
}

TEST_P(PaintArtifactCompositorTest, TransformChange) {
  auto* t1 = Create2DTranslation(t0(), 10, 20);
  auto* t2 = TransformPaintPropertyNode::Create(
      *t1, Transform3dState(MakeRotationMatrix(45)));
  FakeDisplayItemClient& client =
      *MakeGarbageCollected<FakeDisplayItemClient>();
  client.Validate();
  Update(TestPaintArtifact()
             .Chunk(1)
             .Properties(*t2, c0(), e0())
             .RectDrawing(client, gfx::Rect(100, 100, 200, 100), Color::kBlack)
             .Build());
  ASSERT_EQ(1u, LayerCount());
  auto* layer = static_cast<cc::PictureLayer*>(LayerAt(0));
  auto display_item_list = layer->client()->PaintContentsToDisplayList();

  // Change t1 but not t2.
  layer->ClearSubtreePropertyChangedForTesting();
  t1->Update(
      t0(), TransformPaintPropertyNode::State{{MakeTranslationMatrix(20, 30)}});
  EXPECT_EQ(PaintPropertyChangeType::kChangedOnlySimpleValues,
            t1->NodeChanged());
  EXPECT_EQ(PaintPropertyChangeType::kUnchanged, t2->NodeChanged());
  Update(TestPaintArtifact()
             .Chunk(1)
             .Properties(*t2, c0(), e0())
             .RectDrawing(client, gfx::Rect(100, 100, 200, 100), Color::kBlack)
             .Build());

  ASSERT_EQ(1u, LayerCount());
  ASSERT_EQ(layer, LayerAt(0));
  EXPECT_EQ(display_item_list.get(),
            layer->client()->PaintContentsToDisplayList().get());
  EXPECT_TRUE(layer->subtree_property_changed());
  // This is set by cc when propagating ancestor change flag to descendants.
  EXPECT_TRUE(GetTransformNode(layer).transform_changed);
  // This is set by PropertyTreeManager.
  EXPECT_TRUE(GetPropertyTrees()
                  .transform_tree()
                  .Node(GetTransformNode(layer).parent_id)
                  ->transform_changed);

  // Change t2 but not t1.
  layer->ClearSubtreePropertyChangedForTesting();
  t2->Update(*t1, Transform3dState(MakeRotationMatrix(135)));
  EXPECT_EQ(PaintPropertyChangeType::kUnchanged, t1->NodeChanged());
  EXPECT_EQ(PaintPropertyChangeType::kChangedOnlySimpleValues,
            t2->NodeChanged());
  Update(TestPaintArtifact()
             .Chunk(1)
             .Properties(*t2, c0(), e0())
             .RectDrawing(client, gfx::Rect(100, 100, 200, 100), Color::kBlack)
             .Build());

  ASSERT_EQ(1u, LayerCount());
  ASSERT_EQ(layer, LayerAt(0));
  EXPECT_EQ(display_item_list.get(),
            layer->client()->PaintContentsToDisplayList().get());
  EXPECT_TRUE(layer->subtree_property_changed());
  EXPECT_TRUE(GetTransformNode(layer).transform_changed);
  EXPECT_FALSE(GetPropertyTrees()
                   .transform_tree()
                   .Node(GetTransformNode(layer).parent_id)
                   ->transform_changed);

  // Change t2 to be 2d translation which will be decomposited.
  layer->ClearSubtreePropertyChangedForTesting();
  t2->Update(*t1, Transform3dState(MakeTranslationMatrix(20, 30)));
  EXPECT_EQ(PaintPropertyChangeType::kUnchanged, t1->NodeChanged());
  EXPECT_EQ(PaintPropertyChangeType::kChangedOnlyValues, t2->NodeChanged());
  Update(TestPaintArtifact()
             .Chunk(1)
             .Properties(*t2, c0(), e0())
             .RectDrawing(client, gfx::Rect(100, 100, 200, 100), Color::kBlack)
             .Build());

  ASSERT_EQ(1u, LayerCount());
  ASSERT_EQ(layer, LayerAt(0));
  EXPECT_EQ(display_item_list.get(),
            layer->client()->PaintContentsToDisplayList().get());
  // The new transform is decomposited, so there is no transform_changed, but
  // we set subtree_property_changed because offset_from_transform_parent
  // (calculated from the decomposited transforms) changed.
  EXPECT_TRUE(layer->subtree_property_changed());
  EXPECT_FALSE(GetTransformNode(layer).transform_changed);

  // Change no transform nodes, but invalidate client.
  layer->ClearSubtreePropertyChangedForTesting();
  client.Invalidate(PaintInvalidationReason::kBackground);
  Update(TestPaintArtifact()
             .Chunk(1)
             .Properties(*t2, c0(), e0())
             .RectDrawing(client, gfx::Rect(100, 100, 200, 100), Color::kWhite)
             .Build());

  ASSERT_EQ(1u, LayerCount());
  ASSERT_EQ(layer, LayerAt(0));
  EXPECT_NE(display_item_list.get(),
            layer->client()->PaintContentsToDisplayList().get());
}

TEST_P(PaintArtifactCompositorTest, EffectChange) {
  auto* e1 = CreateOpacityEffect(e0(), t0(), nullptr, 0.5f);
  auto* e2 = CreateOpacityEffect(*e1, t0(), nullptr, 0.6f,
                                 CompositingReason::kWillChangeOpacity);

  Update(TestPaintArtifact()
             .Chunk(1)
             .Properties(t0(), c0(), *e2)
             .RectDrawing(gfx::Rect(100, 100, 200, 100), Color::kBlack)
             .Build());
  ASSERT_EQ(1u, LayerCount());
  cc::Layer* layer = LayerAt(0);

  // Change e1 but not e2.
  layer->ClearSubtreePropertyChangedForTesting();
  EffectPaintPropertyNode::State e1_state{&t0()};
  e1_state.opacity = 0.8f;
  e1_state.compositor_element_id = e1->GetCompositorElementId();
  e1->Update(e0(), std::move(e1_state));
  EXPECT_EQ(PaintPropertyChangeType::kChangedOnlySimpleValues,
            e1->NodeChanged());
  EXPECT_EQ(PaintPropertyChangeType::kUnchanged, e2->NodeChanged());
  Update(TestPaintArtifact()
             .Chunk(1)
             .Properties(t0(), c0(), *e2)
             .RectDrawing(gfx::Rect(100, 100, 200, 100), Color::kBlack)
             .Build());

  ASSERT_EQ(1u, LayerCount());
  ASSERT_EQ(layer, LayerAt(0));
  // TODO(wangxianzhu): Probably avoid setting this flag on Effect change.
  EXPECT_TRUE(layer->subtree_property_changed());
  // This is set by cc when propagating ancestor change flag to descendants.
  EXPECT_TRUE(GetEffectNode(layer).effect_changed);
  // This is set by PropertyTreeManager.
  EXPECT_TRUE(GetPropertyTrees()
                  .effect_tree()
                  .Node(GetEffectNode(layer).parent_id)
                  ->effect_changed);

  // Change e2 but not e1.
  layer->ClearSubtreePropertyChangedForTesting();
  EffectPaintPropertyNode::State e2_state{&t0()};
  e2_state.opacity = 0.9f;
  e2_state.direct_compositing_reasons = CompositingReason::kWillChangeOpacity;
  e2_state.compositor_element_id = e2->GetCompositorElementId();
  e2->Update(*e1, std::move(e2_state));
  EXPECT_EQ(PaintPropertyChangeType::kUnchanged, e1->NodeChanged());
  EXPECT_EQ(PaintPropertyChangeType::kChangedOnlySimpleValues,
            e2->NodeChanged());
  Update(TestPaintArtifact()
             .Chunk(1)
             .Properties(t0(), c0(), *e2)
             .RectDrawing(gfx::Rect(100, 100, 200, 100), Color::kBlack)
             .Build());

  ASSERT_EQ(1u, LayerCount());
  ASSERT_EQ(layer, LayerAt(0));
  // TODO(wangxianzhu): Probably avoid setting this flag on Effect change.
  EXPECT_TRUE(layer->subtree_property_changed());
  EXPECT_TRUE(GetEffectNode(layer).effect_changed);
  EXPECT_FALSE(GetPropertyTrees()
                   .effect_tree()
                   .Node(GetEffectNode(layer).parent_id)
                   ->effect_changed);
}

TEST_P(PaintArtifactCompositorTest, DirectlySetScrollOffset) {
  auto scroll_state = ScrollState1();
  auto& scroll = *scroll_state.Transform().ScrollNode();
  auto scroll_element_id = scroll.GetCompositorElementId();

  Update(TestPaintArtifact().ScrollChunks(scroll_state).Build());

  const auto& scroll_tree = GetPropertyTrees().scroll_tree();
  const auto* scroll_layer = ScrollHitTestLayerAt(0);
  const auto* scroll_node =
      scroll_tree.FindNodeFromElementId(scroll_element_id);
  const auto& transform_tree = GetPropertyTrees().transform_tree();
  const auto* transform_node = transform_tree.Node(scroll_node->transform_id);
  EXPECT_EQ(scroll_element_id, scroll_node->element_id);
  EXPECT_EQ(scroll_element_id, scroll_layer->element_id());
  EXPECT_EQ(scroll_node->id, scroll_layer->scroll_tree_index());
  EXPECT_EQ(gfx::PointF(-7, -9),
            scroll_tree.current_scroll_offset(scroll_element_id));
  EXPECT_EQ(gfx::PointF(-7, -9), transform_node->scroll_offset);

  auto& host = GetLayerTreeHost();
  host.CompositeForTest(base::TimeTicks::Now(), true, base::OnceClosure());
  ASSERT_FALSE(const_cast<const cc::LayerTreeHost&>(host)
                   .pending_commit_state()
                   ->layers_that_should_push_properties.contains(scroll_layer));
  ASSERT_FALSE(host.CommitRequested());
  ASSERT_FALSE(transform_tree.needs_update());

  ASSERT_TRUE(GetPaintArtifactCompositor().DirectlySetScrollOffset(
      scroll_element_id, gfx::PointF(-10, -20)));
  EXPECT_TRUE(const_cast<const cc::LayerTreeHost&>(host)
                  .pending_commit_state()
                  ->layers_that_should_push_properties.contains(scroll_layer));
  EXPECT_TRUE(host.CommitRequested());
  EXPECT_EQ(gfx::PointF(-10, -20),
            scroll_tree.current_scroll_offset(scroll_element_id));
  // DirectlySetScrollOffset doesn't update transform node.
  EXPECT_EQ(gfx::PointF(-7, -9), transform_node->scroll_offset);
  EXPECT_FALSE(transform_tree.needs_update());
}

TEST_P(PaintArtifactCompositorTest, NoCommitRequestForUnchangedScroll) {
  auto& host = GetLayerTreeHost();
  auto scroll_state = ScrollState1();
  auto& scroll_node = *scroll_state.Transform().ScrollNode();
  EXPECT_EQ(PaintPropertyChangeType::kNodeAddedOrRemoved,
            scroll_node.NodeChanged());

  auto* client = MakeGarbageCollected<FakeDisplayItemClient>("client");
  Update(TestPaintArtifact().ScrollHitTestChunk(*client, scroll_state).Build());
  EXPECT_EQ(PaintPropertyChangeType::kUnchanged, scroll_node.NodeChanged());
  EXPECT_TRUE(host.CommitRequested());

  host.CompositeForTest(base::TimeTicks::Now(), true, base::OnceClosure());
  EXPECT_FALSE(host.CommitRequested());

  // Update with a paint artifact with the same content.
  Update(TestPaintArtifact().ScrollHitTestChunk(*client, scroll_state).Build());
  // This update should not SetNeedsCommit().
  EXPECT_FALSE(host.CommitRequested());
}

TEST_P(PaintArtifactCompositorTest, AddIndirectlyCompositedScrollNodes) {
  auto scroll_state =
      ScrollState1(PropertyTreeState::Root(), CompositingReason::kNone,
                   cc::MainThreadScrollingReason::kNotScrollingOnMain);
  PaintArtifactCompositor::StackScrollTranslationVector
      scroll_translation_nodes = {&scroll_state.Transform()};

  Update(TestPaintArtifact()
             // Opaque contents make the scroll composited.
             .ScrollChunks(scroll_state, /*contents_opaque=*/true)
             .Build(),
         ViewportProperties(), scroll_translation_nodes);

  const auto& scroll_tree = GetPropertyTrees().scroll_tree();
  auto* scroll_node = scroll_tree.FindNodeFromElementId(
      scroll_state.Transform().ScrollNode()->GetCompositorElementId());
  ASSERT_TRUE(scroll_node);
  EXPECT_TRUE(scroll_node->is_composited);
  EXPECT_EQ(cc::MainThreadScrollingReason::kNotScrollingOnMain,
            scroll_node->main_thread_repaint_reasons);
  EXPECT_TRUE(scroll_tree.CanRealizeScrollsOnActiveTree(*scroll_node));
  EXPECT_FALSE(scroll_tree.CanRealizeScrollsOnPendingTree(*scroll_node));
  EXPECT_FALSE(scroll_tree.ShouldRealizeScrollsOnMain(*scroll_node));
}

TEST_P(PaintArtifactCompositorTest, AddNonCompositedScrollNodes) {
  auto scroll_state =
      ScrollState1(PropertyTreeState::Root(), CompositingReason::kNone,
                   cc::MainThreadScrollingReason::kNotScrollingOnMain);
  PaintArtifactCompositor::StackScrollTranslationVector
      scroll_translation_nodes = {&scroll_state.Transform()};

  Update(TestPaintArtifact().ScrollChunks(scroll_state).Build(),
         ViewportProperties(), scroll_translation_nodes);

  const auto& scroll_tree = GetPropertyTrees().scroll_tree();
  auto* scroll_node = scroll_tree.FindNodeFromElementId(
      scroll_state.Transform().ScrollNode()->GetCompositorElementId());
  ASSERT_TRUE(scroll_node);
  EXPECT_FALSE(scroll_node->is_composited);
  EXPECT_FALSE(scroll_tree.CanRealizeScrollsOnActiveTree(*scroll_node));
  if (RuntimeEnabledFeatures::RasterInducingScrollEnabled()) {
    EXPECT_EQ(cc::MainThreadScrollingReason::kNotScrollingOnMain,
              scroll_node->main_thread_repaint_reasons);
    EXPECT_TRUE(scroll_tree.CanRealizeScrollsOnPendingTree(*scroll_node));
    EXPECT_FALSE(scroll_tree.ShouldRealizeScrollsOnMain(*scroll_node));
  } else {
    EXPECT_EQ(cc::MainThreadScrollingReason::kNotOpaqueForTextAndLCDText,
              scroll_node->main_thread_repaint_reasons);
    EXPECT_FALSE(scroll_tree.CanRealizeScrollsOnPendingTree(*scroll_node));
    EXPECT_TRUE(scroll_tree.ShouldRealizeScrollsOnMain(*scroll_node));
  }
}

TEST_P(PaintArtifactCompositorTest, AddNonCompositedMainThreadScrollNodes) {
  auto scroll_state = ScrollState1(
      PropertyTreeState::Root(), CompositingReason::kNone,
      cc::MainThreadScrollingReason::kHasBackgroundAttachmentFixedObjects);
  PaintArtifactCompositor::StackScrollTranslationVector
      scroll_translation_nodes = {&scroll_state.Transform()};

  Update(TestPaintArtifact().ScrollChunks(scroll_state).Build(),
         ViewportProperties(), scroll_translation_nodes);

  const auto& scroll_tree = GetPropertyTrees().scroll_tree();
  auto* scroll_node = scroll_tree.FindNodeFromElementId(
      scroll_state.Transform().ScrollNode()->GetCompositorElementId());
  ASSERT_TRUE(scroll_node);
  EXPECT_FALSE(scroll_node->is_composited);
  if (RuntimeEnabledFeatures::RasterInducingScrollEnabled()) {
    EXPECT_EQ(
        cc::MainThreadScrollingReason::kHasBackgroundAttachmentFixedObjects,
        scroll_node->main_thread_repaint_reasons);
  } else {
    EXPECT_EQ(
        cc::MainThreadScrollingReason::kNotOpaqueForTextAndLCDText |
            cc::MainThreadScrollingReason::kHasBackgroundAttachmentFixedObjects,
        scroll_node->main_thread_repaint_reasons);
  }
  EXPECT_FALSE(scroll_tree.CanRealizeScrollsOnActiveTree(*scroll_node));
  EXPECT_FALSE(scroll_tree.CanRealizeScrollsOnPendingTree(*scroll_node));
  EXPECT_TRUE(scroll_tree.ShouldRealizeScrollsOnMain(*scroll_node));
}

TEST_P(PaintArtifactCompositorTest,
       AddIndirectlyCompositedMainThreadScrollNodes) {
  auto scroll_state = ScrollState1(
      PropertyTreeState::Root(), CompositingReason::kNone,
      cc::MainThreadScrollingReason::kHasBackgroundAttachmentFixedObjects);
  PaintArtifactCompositor::StackScrollTranslationVector
      scroll_translation_nodes = {&scroll_state.Transform()};

  Update(TestPaintArtifact()
             // Opaque contents make the scroll composited.
             .ScrollChunks(scroll_state, /*contents_opaque=*/true)
             .Build(),
         ViewportProperties(), scroll_translation_nodes);

  const auto& scroll_tree = GetPropertyTrees().scroll_tree();
  auto* scroll_node = scroll_tree.FindNodeFromElementId(
      scroll_state.Transform().ScrollNode()->GetCompositorElementId());
  ASSERT_TRUE(scroll_node);
  // THe scroll node should realize on main thread despite is_composited.
  EXPECT_TRUE(scroll_node->is_composited);
  EXPECT_EQ(cc::MainThreadScrollingReason::kHasBackgroundAttachmentFixedObjects,
            scroll_node->main_thread_repaint_reasons);
  EXPECT_FALSE(scroll_tree.CanRealizeScrollsOnActiveTree(*scroll_node));
  EXPECT_FALSE(scroll_tree.CanRealizeScrollsOnPendingTree(*scroll_node));
  EXPECT_TRUE(scroll_tree.ShouldRealizeScrollsOnMain(*scroll_node));
}

TEST_P(PaintArtifactCompositorTest, AddUnpaintedNonCompositedScrollNodes) {
  const uint32_t main_thread_scrolling_reason =
      cc::MainThreadScrollingReason::kNotOpaqueForTextAndLCDText;
  auto scroll_state =
      ScrollState1(PropertyTreeState::Root(), CompositingReason::kNone,
                   main_thread_scrolling_reason);
  PaintArtifactCompositor::StackScrollTranslationVector
      scroll_translation_nodes = {&scroll_state.Transform()};

  Update(TestPaintArtifact().Build(), ViewportProperties(),
         scroll_translation_nodes);

  const auto& scroll_tree = GetPropertyTrees().scroll_tree();
  auto* scroll_node = scroll_tree.FindNodeFromElementId(
      scroll_state.Transform().ScrollNode()->GetCompositorElementId());
  ASSERT_TRUE(scroll_node);
  EXPECT_FALSE(scroll_node->is_composited);
  EXPECT_EQ(scroll_node->transform_id, cc::kInvalidPropertyNodeId);
  EXPECT_EQ(gfx::PointF(-7, -9),
            scroll_tree.current_scroll_offset(scroll_node->element_id));
  EXPECT_FALSE(scroll_tree.CanRealizeScrollsOnActiveTree(*scroll_node));
  EXPECT_FALSE(scroll_tree.CanRealizeScrollsOnPendingTree(*scroll_node));
  EXPECT_FALSE(scroll_tree.ShouldRealizeScrollsOnMain(*scroll_node));
}

TEST_P(PaintArtifactCompositorTest, RepaintIndirectScrollHitTest) {
  auto scroll_state = ScrollState1();
  auto& artifact = TestPaintArtifact().ScrollHitTestChunk(scroll_state).Build();
  auto& host = GetLayerTreeHost();

  Update(artifact);
  EXPECT_TRUE(host.CommitRequested());

  host.CompositeForTest(base::TimeTicks::Now(), true, base::OnceClosure());
  EXPECT_FALSE(host.CommitRequested());

  GetPaintArtifactCompositor().UpdateRepaintedLayers(artifact);
  EXPECT_FALSE(host.CommitRequested());
}

TEST_P(PaintArtifactCompositorTest, ClearChangedStateWithIndirectTransform) {
  // t1 and t2 are siblings.
  auto* t1 = Create2DTranslation(t0(), 1, 1);
  auto* t2 = Create2DTranslation(t0(), 2, 2);
  // c1 and c2 are parent and child, referencing t1 and t2, respectively.
  auto* c1 = CreateClip(c0(), *t1, FloatRoundedRect(1, 1, 1, 1));
  auto* c2 = CreateClip(*c1, *t2, FloatRoundedRect(2, 2, 2, 2));
  EXPECT_EQ(PaintPropertyChangeType::kNodeAddedOrRemoved, t1->NodeChanged());
  EXPECT_EQ(PaintPropertyChangeType::kNodeAddedOrRemoved, t2->NodeChanged());
  EXPECT_EQ(PaintPropertyChangeType::kNodeAddedOrRemoved, c1->NodeChanged());
  EXPECT_EQ(PaintPropertyChangeType::kNodeAddedOrRemoved, c2->NodeChanged());

  auto& artifact = TestPaintArtifact()
                       .Chunk(1)
                       .Properties(*t2, *c2, e0())
                       .RectDrawing(gfx::Rect(2, 2, 2, 2), Color::kBlack)
                       .Build();
  Update(artifact);
  EXPECT_EQ(PaintPropertyChangeType::kUnchanged, t1->NodeChanged());
  EXPECT_EQ(PaintPropertyChangeType::kUnchanged, t2->NodeChanged());
  EXPECT_EQ(PaintPropertyChangeType::kUnchanged, c1->NodeChanged());
  EXPECT_EQ(PaintPropertyChangeType::kUnchanged, c2->NodeChanged());

  GetPaintArtifactCompositor().UpdateRepaintedLayers(artifact);
  // This test passes if no DCHECK occurs.
}

TEST_P(PaintArtifactCompositorTest,
       CompositedPixelMovingFilterWithClipExpander) {
  CompositorFilterOperations filter_op;
  filter_op.AppendBlurFilter(5);
  auto* filter =
      CreateFilterEffect(e0(), filter_op, CompositingReason::kWillChangeFilter);
  auto* clip_expander = CreatePixelMovingFilterClipExpander(c0(), *filter);

  Update(TestPaintArtifact()
             .Chunk(t0(), *clip_expander, *filter)
             .RectDrawing(gfx::Rect(150, 150, 100, 100), Color::kWhite)
             .Build());
  ASSERT_EQ(1u, LayerCount());
  const auto* cc_clip_expander =
      GetPropertyTrees().clip_tree().Node(LayerAt(0)->clip_tree_index());
  EXPECT_FALSE(cc_clip_expander->AppliesLocalClip());
  EXPECT_EQ(cc_clip_expander->pixel_moving_filter_id,
            LayerAt(0)->effect_tree_index());
}

TEST_P(PaintArtifactCompositorTest,
       NonCompositedPixelMovingFilterWithCompositedClipExpander) {
  CompositorFilterOperations filter_op;
  filter_op.AppendBlurFilter(5);
  auto* filter = CreateFilterEffect(e0(), filter_op);
  auto* clip_expander = CreatePixelMovingFilterClipExpander(c0(), *filter);

  EffectPaintPropertyNode::State mask_state;
  mask_state.local_transform_space = &t0();
  mask_state.output_clip = clip_expander;
  mask_state.blend_mode = SkBlendMode::kDstIn;
  mask_state.direct_compositing_reasons =
      CompositingReason::kBackdropFilterMask;
  auto* mask = EffectPaintPropertyNode::Create(e0(), std::move(mask_state));

  Update(TestPaintArtifact()
             .Chunk(t0(), *clip_expander, *filter)
             .RectDrawing(gfx::Rect(150, 150, 100, 100), Color::kWhite)
             .Chunk(t0(), *clip_expander, *mask)
             .RectDrawing(gfx::Rect(150, 150, 100, 100), Color::kBlack)
             .Build());
  ASSERT_EQ(2u, LayerCount());
  const auto* cc_clip_expander =
      GetPropertyTrees().clip_tree().Node(LayerAt(0)->clip_tree_index());
  EXPECT_TRUE(cc_clip_expander->AppliesLocalClip());
}

TEST_P(PaintArtifactCompositorTest,
       CreatePictureLayerForSolidColorBackdropFilterMask) {
  CompositorFilterOperations filter;
  filter.AppendBlurFilter(5);
  auto* backdrop_filter = CreateBackdropFilterEffect(e0(), filter);

  EffectPaintPropertyNode::State mask_state;
  mask_state.local_transform_space = &t0();
  mask_state.output_clip = &c0();
  mask_state.blend_mode = SkBlendMode::kDstIn;
  mask_state.direct_compositing_reasons =
      CompositingReason::kBackdropFilterMask;
  auto* mask =
      EffectPaintPropertyNode::Create(*backdrop_filter, std::move(mask_state));

  Update(TestPaintArtifact()
             .Chunk(t0(), c0(), *backdrop_filter)
             .RectDrawing(gfx::Rect(150, 150, 100, 100), Color::kWhite)
             .Chunk(t0(), c0(), *mask)
             .RectDrawing(gfx::Rect(150, 150, 100, 100), Color::kBlack)
             .IsSolidColor()
             .Build());
  ASSERT_EQ(2u, LayerCount());
  EXPECT_FALSE(LayerAt(1)->IsSolidColorLayerForTesting());
}

}  // namespace
}  // namespace blink
```