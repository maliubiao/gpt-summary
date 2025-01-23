Response:
The user wants to understand the functionality of the provided C++ code snippet from a Chromium Blink engine test file. The goal is to explain what the code does, its relationship to web technologies (JavaScript, HTML, CSS), provide examples of logical reasoning with input and output, highlight common user/programming errors, and summarize the overall functionality of this specific part.

Here's a breakdown of the thought process:

1. **Identify the Core Functionality:** The code snippet consists of several test cases (`TEST_P`) within a larger test fixture (`PaintArtifactCompositorTest`). These test cases are designed to verify the behavior of a component likely responsible for taking "paint artifacts" (representing drawing instructions) and translating them into composited layers that can be rendered efficiently.

2. **Analyze Individual Test Cases:** Go through each `TEST_P` block and determine what it's specifically testing:
    * **`ClippedDrawing`:**  This test seems to verify that when drawing within a clipped region, the resulting composited layer is correctly sized and positioned, and that the drawing is clipped as expected.
    * **`SiblingClipsWithAlias`:**  This test explores how multiple drawing operations with different *aliases* to the same underlying clip definition are handled. The key here is "alias," suggesting optimization where redundant clip definitions are not duplicated.
    * **`SiblingClipsWithCompositedTransform`:** This case examines what happens when sibling drawing operations have clips with non-mergeable transforms. This suggests that some optimizations or merging cannot occur in such scenarios.
    * **`SiblingTransformsWithAlias`:** Similar to the clip alias test, this checks how aliased transforms on sibling drawings are handled.
    * **`SiblingTransformsWithComposited`:** This mirrors the composited clip test, focusing on non-mergeable transforms and their impact on layer creation.
    * **`ForeignLayerPassesThrough`:** This tests the ability to incorporate existing `cc::Layer` objects directly into the compositing process.
    * **`EffectTreeConversionWithAlias`:**  This test verifies how effect properties (like opacity) are handled when aliases are involved, ensuring the correct structure in the `cc::EffectTree`.
    * **Scrolling Tests (`OneScrollNodeComposited`, `OneScrollNodeNonComposited`, etc.):**  These form a significant part and test the creation and management of composited scrolling layers and their associated `cc::ScrollNode`s and `cc::TransformNode`s. They cover scenarios with and without compositing, nested scrolling, and different orderings of scroll node creation.

3. **Relate to Web Technologies:** Connect the test scenarios to concepts in HTML, CSS, and JavaScript:
    * **Clipping:** Directly relates to the CSS `clip-path` property or the older `clip` property, which define visible regions of elements.
    * **Transforms:**  Corresponds to CSS transforms (e.g., `translate`, `scale`, `rotate`). The tests explore both simple and more complex composited transforms (often triggered by `will-change: transform` or similar).
    * **Opacity:** Directly links to the CSS `opacity` property.
    * **Scrolling:**  Fundamental to web pages, tested here in the context of composited scrolling (smooth scrolling off the main thread). This relates to the `overflow` property in CSS and browser optimizations for scrolling performance.
    * **Layers:**  Although not a direct web technology, the concept of composited layers is crucial for browser rendering performance. CSS properties like `transform`, `opacity`, `filter`, and `will-change` can trigger layer creation.
    * **Foreign Layers:**  This might relate to embedding external content or using browser APIs that provide pre-rendered content.

4. **Provide Examples of Logical Reasoning:** For specific tests, create hypothetical inputs (based on the `TestPaintArtifact` setup) and predict the outputs (number of layers, their properties, contents of the `cc::Picture`). Focus on the core assertion of the test.

5. **Identify Potential User/Programming Errors:** Think about how developers might misuse the concepts being tested:
    * **Incorrect Clipping:**  Setting `clip-path` or `clip` incorrectly, leading to unexpected visibility.
    * **Misunderstanding Compositing:**  Expecting elements to be on separate layers when they aren't, or vice-versa, leading to performance issues.
    * **Incorrect Transform Origins:** Setting the transform origin in a way that produces unexpected transformations.
    * **Conflicting Transforms:** Applying multiple conflicting transforms that don't combine as intended.
    * **Forgetting `will-change`:**  Not using `will-change` when necessary for performance-critical animations/transitions.
    * **Overusing `will-change`:**  Applying `will-change` unnecessarily, potentially wasting resources.
    * **Incorrect Scroll Container Setup:**  Not setting `overflow: auto` or `overflow: scroll` on the intended scrolling element.

6. **Summarize Functionality:** Condense the analysis into a concise description of the code's purpose. Emphasize that it's testing the `PaintArtifactCompositor`'s ability to translate drawing instructions and property information into a composited layer structure.

7. **Structure the Answer:** Organize the information clearly with headings for each aspect requested by the user (Functionality, Relationship to Web Technologies, Logical Reasoning, User Errors, Summary).

By following these steps, a comprehensive and informative answer can be generated that addresses all the user's requirements.
这是对`blink/renderer/platform/graphics/compositing/paint_artifact_compositor_test.cc` 文件中一部分代码的分析，主要关注了 **剪裁 (Clip)**, **变换 (Transform)**, **特效 (Effect)** 和 **滚动 (Scroll)** 属性对图层合成的影响，以及如何处理外部图层。

**功能归纳:**

这部分代码主要测试 `PaintArtifactCompositor` 在处理以下场景时的行为：

* **剪裁 (Clip):**
    * **基本剪裁:** 验证绘制内容是否被正确的剪裁区域限制。
    * **共享剪裁 (Alias):** 测试当多个绘制操作引用同一个剪裁属性节点时，合成器如何优化处理，避免重复创建剪裁图层。
    * **带变换的剪裁:** 测试当剪裁区域本身带有不可合并的变换时，合成器是否会为每个剪裁区域创建单独的图层。
* **变换 (Transform):**
    * **共享变换 (Alias):** 测试当多个绘制操作引用同一个变换属性节点时，合成器如何优化处理，合并到同一个图层并应用变换。
    * **不可合并的变换:** 测试当多个绘制操作带有不可合并的变换时，合成器是否会为每个变换创建单独的图层。
* **外部图层 (Foreign Layer):** 测试 `PaintArtifactCompositor` 是否能正确地将外部已有的 `cc::Layer` 对象集成到合成结果中。
* **特效 (Effect):**
    * **共享特效 (Alias):** 测试当多个绘制操作引用同一个特效属性节点（例如 opacity）时，合成器如何在特效树中正确构建层级关系。
* **滚动 (Scroll):**
    * **合成滚动:** 测试当元素具有合成滚动属性时，`PaintArtifactCompositor` 如何创建 `cc::ScrollNode` 和相关的图层。
    * **非合成滚动:** 测试非合成滚动的情况，以及 `cc::ScrollNode` 和 `cc::TransformNode` 的创建。
    * **滚动容器内的变换:** 测试在滚动容器内部应用变换的情况，以及图层的剪裁行为。
    * **嵌套滚动:** 测试嵌套滚动容器的场景，以及 `cc::ScrollNode` 的父子关系。
    * **滚动层叠顺序:** 测试滚动相关的图层在合成结果中的层叠顺序。
    * **祖先滚动容器:** 测试父级和子级都是滚动容器的情况，包括合成和非合成的场景，以及滚动节点创建的顺序。
    * **不同的变换树和滚动树层级:** 测试滚动容器的变换和滚动父节点不在同一个层级的情况。

**与 Javascript, HTML, CSS 的关系及举例说明:**

这些测试用例直接关系到浏览器如何将 HTML 结构、CSS 样式和可能的 Javascript 动画转化为最终屏幕上渲染的内容。

* **HTML:**  HTML 定义了页面的结构，其中的元素会根据 CSS 样式进行绘制。例如，一个 `<div>` 元素可能因为设置了 `overflow: auto` 而成为一个滚动容器。
* **CSS:**
    * **`clip-path` 或 `clip`:**  这些 CSS 属性定义了元素的剪裁区域，对应了 `ClippedDrawing` 和 `SiblingClipsWithAlias` 等测试用例。 例如，`clip-path: polygon(0 0, 100px 0, 100px 100px, 0 100px);` 会将元素剪裁成一个正方形。
    * **`transform`:**  CSS 的 `transform` 属性（如 `translate`, `rotate`, `scale`）对应了 `SiblingTransformsWithAlias` 和 `SiblingTransformsWithComposited` 等测试用例。 例如，`transform: translateX(50px);` 会将元素水平移动 50 像素。
    * **`opacity`:** CSS 的 `opacity` 属性对应了 `EffectTreeConversionWithAlias` 测试用例。例如，`opacity: 0.5;` 会使元素半透明。
    * **`overflow: auto` 或 `overflow: scroll`:**  这些 CSS 属性会使元素成为滚动容器，对应了大量的滚动相关的测试用例。
    * **`will-change`:**  虽然代码中没有直接体现，但 `CompositingReason::kWillChangeTransform` 等可能与 CSS 的 `will-change` 属性有关，该属性可以提示浏览器提前将元素放到独立的合成层，以优化性能。
* **Javascript:** Javascript 可以动态地修改元素的 CSS 样式，包括剪裁、变换、透明度以及滚动位置。例如，通过 Javascript 可以动态地改变元素的 `transform` 属性来实现动画效果。

**逻辑推理的假设输入与输出:**

**假设输入 (基于 `ClippedDrawing` 测试):**

* 创建一个 `PaintArtifact` 对象。
* 向其中添加一个绘制指令，绘制一个白色矩形，坐标为 (0, 0, 200, 200)。
* 创建两个嵌套的剪裁属性节点，`clips` 向量中包含了这些节点，模拟 CSS 中的嵌套 `clip-path` 或祖先元素的 `overflow: hidden` 效果。
* 调用 `Update()` 方法进行合成。

**预期输出:**

* 合成结果中应该只有一个图层 (`LayerCount() == 1u`)。
* 该图层的尺寸应该与最外层剪裁区域一致 (`EXPECT_EQ(gfx::Size(100, 100), drawing_layer->bounds())`)。
* 图层相对于其变换父节点的偏移应该考虑了剪裁区域的位置 (`EXPECT_EQ(gfx::Vector2dF(50, 0), drawing_layer->offset_to_transform_parent())`)。
* 图层实际绘制的内容应该被所有剪裁区域约束，因此绘制的矩形会被剪裁 (`EXPECT_THAT(drawing_layer->GetPicture(), Pointee(DrawsRectangle(gfx::RectF(0, 0, 150, 200), Color::kWhite))))`)。注意，这里的尺寸是相对于图层自身的坐标系。
* 图层的屏幕空间变换应该考虑了偏移 (`EXPECT_EQ(Translation(50, 0), drawing_layer->ScreenSpaceTransform())`)。
* 合成器应该创建了对应的 `cc::ClipNode`，并且这些节点的属性应该与 `clips` 向量中的剪裁属性节点一致，并形成正确的父子关系。

**涉及用户或者编程常见的使用错误 (举例说明):**

* **错误地理解剪裁区域:** 用户可能认为绘制的坐标是相对于最终屏幕的，而忽略了剪裁区域的影响，导致部分内容不可见。 例如，在一个设置了 `clip-path: inset(10px);` 的元素内绘制一个从 (0,0) 开始的矩形，矩形的左上角会被剪掉。
* **过度使用 `will-change`:**  程序员可能会为了“优化”而对所有元素都设置 `will-change: transform` 或其他属性，导致不必要的图层创建，反而降低性能并占用更多内存。
* **忘记设置滚动容器:** 用户可能期望某个区域可以滚动，但忘记在 CSS 中设置 `overflow: auto` 或 `overflow: scroll`，导致内容溢出而不是出现滚动条。
* **变换原点 (transform-origin) 的混淆:**  不理解 `transform-origin` 的作用，导致变换效果与预期不符。例如，旋转一个元素时，如果 `transform-origin` 不是中心点，元素会围绕非中心点旋转。
* **滚动穿透 (Scroll Chaining/Snapping) 的误解:**  不理解浏览器默认的滚动行为，或者没有正确配置滚动捕捉 (Scroll Snapping) 相关的 CSS 属性，导致滚动体验不佳。

总而言之，这部分代码深入测试了 Blink 引擎中负责将绘制指令和各种视觉属性转化为可供合成器使用的图层结构的组件，确保了网页内容能够被正确且高效地渲染到屏幕上。 这些测试涵盖了 CSS 中常见的视觉效果和布局方式，对于保证浏览器的渲染质量和性能至关重要。

### 提示词
```
这是目录为blink/renderer/platform/graphics/compositing/paint_artifact_compositor_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
tArtifact artifact;
  artifact.Chunk(t0(), *clips.back(), e0())
      .RectDrawing(gfx::Rect(0, 0, 200, 200), Color::kWhite);
  Update(artifact.Build());

  // Check the drawing layer. It's clipped.
  ASSERT_EQ(1u, LayerCount());
  const cc::Layer* drawing_layer = LayerAt(0);
  EXPECT_EQ(gfx::Size(100, 100), drawing_layer->bounds());
  EXPECT_EQ(gfx::Vector2dF(50, 0), drawing_layer->offset_to_transform_parent());
  EXPECT_THAT(
      drawing_layer->GetPicture(),
      Pointee(DrawsRectangle(gfx::RectF(0, 0, 150, 200), Color::kWhite)));
  EXPECT_EQ(Translation(50, 0), drawing_layer->ScreenSpaceTransform());

  // Check the clip nodes.
  const cc::ClipNode* clip_node =
      GetPropertyTrees().clip_tree().Node(drawing_layer->clip_tree_index());
  for (const auto& paint_clip_node : base::Reversed(clips)) {
    EXPECT_TRUE(clip_node->AppliesLocalClip());
    EXPECT_EQ(paint_clip_node->PaintClipRect().Rect(), clip_node->clip);
    clip_node = GetPropertyTrees().clip_tree().Node(clip_node->parent_id);
  }
}

TEST_P(PaintArtifactCompositorTest, SiblingClipsWithAlias) {
  auto* real_common_clip =
      CreateClip(c0(), t0(), FloatRoundedRect(0, 0, 80, 60));
  auto* common_clip = ClipPaintPropertyNodeAlias::Create(*real_common_clip);
  auto* real_clip1 =
      CreateClip(*common_clip, t0(), FloatRoundedRect(0, 0, 30, 20));
  auto* clip1 = ClipPaintPropertyNodeAlias::Create(*real_clip1);
  auto* real_clip2 =
      CreateClip(*common_clip, t0(), FloatRoundedRect(40, 0, 40, 60));
  auto* clip2 = ClipPaintPropertyNodeAlias::Create(*real_clip2);

  TestPaintArtifact artifact;
  artifact.Chunk(t0(), *clip1, e0())
      .RectDrawing(gfx::Rect(0, 0, 11, 22), Color::kWhite);
  artifact.Chunk(t0(), *clip2, e0())
      .RectDrawing(gfx::Rect(33, 44, 55, 66), Color::kBlack);
  Update(artifact.Build());

  // The two chunks are merged together.
  ASSERT_EQ(1u, LayerCount());
  const cc::Layer* layer = LayerAt(0);
  EXPECT_THAT(layer->GetPicture(),
              Pointee(DrawsRectangles(Vector<RectWithColor>{
                  // This is the first RectDrawing with real_clip1 applied.
                  RectWithColor(gfx::RectF(0, 0, 11, 20), Color::kWhite),
                  // This is the second RectDrawing with real_clip2 applied.
                  RectWithColor(gfx::RectF(40, 44, 40, 16), Color::kBlack)})));
  EXPECT_EQ(gfx::Transform(), layer->ScreenSpaceTransform());
  const cc::ClipNode* clip_node =
      GetPropertyTrees().clip_tree().Node(layer->clip_tree_index());
  EXPECT_TRUE(clip_node->AppliesLocalClip());
  ASSERT_EQ(gfx::RectF(0, 0, 80, 60), clip_node->clip);
}

TEST_P(PaintArtifactCompositorTest, SiblingClipsWithCompositedTransform) {
  auto* t1 = CreateTransform(t0(), gfx::Transform(), gfx::Point3F(),
                             CompositingReason::kWillChangeTransform);
  auto* t2 = CreateTransform(*t1, MakeTranslationMatrix(1, 2));
  auto* c1 = CreateClip(c0(), t0(), FloatRoundedRect(0, 0, 400, 600));
  auto* c2 = CreateClip(c0(), *t2, FloatRoundedRect(400, 0, 400, 600));

  TestPaintArtifact artifact;
  artifact.Chunk(t0(), *c1, e0())
      .RectDrawing(gfx::Rect(0, 0, 640, 480), Color::kWhite);
  artifact.Chunk(t0(), *c2, e0())
      .RectDrawing(gfx::Rect(0, 0, 640, 480), Color::kBlack);
  Update(artifact.Build());

  // We can't merge the two chunks because their clips have unmergeable
  // transforms.
  ASSERT_EQ(2u, LayerCount());
}

TEST_P(PaintArtifactCompositorTest, SiblingTransformsWithAlias) {
  auto* real_common_transform =
      CreateTransform(t0(), MakeTranslationMatrix(5, 6));
  auto* common_transform =
      TransformPaintPropertyNodeAlias::Create(*real_common_transform);
  auto* real_transform1 =
      CreateTransform(*common_transform, MakeScaleMatrix(2));
  auto* transform1 = TransformPaintPropertyNodeAlias::Create(*real_transform1);
  auto* real_transform2 =
      CreateTransform(*common_transform, MakeScaleMatrix(0.5));
  auto* transform2 = TransformPaintPropertyNodeAlias::Create(*real_transform2);

  TestPaintArtifact artifact;
  artifact.Chunk(*transform1, c0(), e0())
      .RectDrawing(gfx::Rect(0, 0, 111, 222), Color::kWhite);
  artifact.Chunk(*transform2, c0(), e0())
      .RectDrawing(gfx::Rect(0, 0, 333, 444), Color::kBlack);
  Update(artifact.Build());

  // The two chunks are merged together.
  ASSERT_EQ(1u, LayerCount());
  const cc::Layer* layer = LayerAt(0);
  EXPECT_THAT(
      layer->GetPicture(),
      Pointee(DrawsRectangles(Vector<RectWithColor>{
          RectWithColor(gfx::RectF(0, 0, 222, 444), Color::kWhite),
          RectWithColor(gfx::RectF(0, 0, 166.5, 222), Color::kBlack)})));
  gfx::Transform expected_transform;
  expected_transform.Translate(5, 6);
  EXPECT_EQ(expected_transform, layer->ScreenSpaceTransform());
}

TEST_P(PaintArtifactCompositorTest, SiblingTransformsWithComposited) {
  auto* t1 = CreateTransform(t0(), gfx::Transform(), gfx::Point3F(),
                             CompositingReason::kWillChangeTransform);
  auto* t2 = CreateTransform(*t1, MakeTranslationMatrix(1, 2));
  auto* t3 = CreateTransform(t0(), MakeTranslationMatrix(3, 4));

  TestPaintArtifact artifact;
  artifact.Chunk(*t2, c0(), e0())
      .RectDrawing(gfx::Rect(0, 0, 640, 480), Color::kWhite);
  artifact.Chunk(*t3, c0(), e0())
      .RectDrawing(gfx::Rect(0, 0, 640, 480), Color::kBlack);
  Update(artifact.Build());

  // We can't merge the two chunks because their transforms are not mergeable.
  ASSERT_EQ(2u, LayerCount());
}

TEST_P(PaintArtifactCompositorTest, ForeignLayerPassesThrough) {
  scoped_refptr<cc::Layer> layer = cc::Layer::Create();
  layer->SetIsDrawable(true);
  layer->SetBounds(gfx::Size(400, 300));

  TestPaintArtifact test_artifact;
  test_artifact.Chunk().RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kWhite);
  test_artifact.Chunk().ForeignLayer(layer, gfx::Point(50, 60));
  test_artifact.Chunk().RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kGray);

  auto& artifact = test_artifact.Build();
  ASSERT_EQ(3u, artifact.GetPaintChunks().size());
  Update(artifact);

  ASSERT_EQ(3u, LayerCount());
  EXPECT_EQ(layer, LayerAt(1));
  EXPECT_EQ(gfx::Size(400, 300), layer->bounds());
  EXPECT_EQ(Translation(50, 60), layer->ScreenSpaceTransform());
}

TEST_P(PaintArtifactCompositorTest, EffectTreeConversionWithAlias) {
  Update(TestPaintArtifact()
             .Chunk()
             .RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kWhite)
             .Build());
  auto root_element_id = GetPropertyTrees().effect_tree().Node(1)->element_id;

  auto* real_effect1 =
      CreateOpacityEffect(e0(), t0(), &c0(), 0.5, CompositingReason::kAll);
  auto* effect1 = EffectPaintPropertyNodeAlias::Create(*real_effect1);
  auto* real_effect2 =
      CreateOpacityEffect(*effect1, 0.3, CompositingReason::kAll);
  auto* effect2 = EffectPaintPropertyNodeAlias::Create(*real_effect2);
  auto* real_effect3 = CreateOpacityEffect(e0(), 0.2, CompositingReason::kAll);
  auto* effect3 = EffectPaintPropertyNodeAlias::Create(*real_effect3);

  TestPaintArtifact artifact;
  artifact.Chunk(t0(), c0(), *effect2)
      .RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kWhite);
  artifact.Chunk(t0(), c0(), *effect1)
      .RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kWhite);
  artifact.Chunk(t0(), c0(), *effect3)
      .RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kWhite);
  Update(artifact.Build());

  ASSERT_EQ(3u, LayerCount());

  const cc::EffectTree& effect_tree = GetPropertyTrees().effect_tree();
  // Node #0 reserved for null; #1 for root render surface; #2 for e0(),
  // plus 3 nodes for those created by this test.
  ASSERT_EQ(5u, effect_tree.size());

  const cc::EffectNode& converted_root_effect = *effect_tree.Node(1);
  EXPECT_EQ(-1, converted_root_effect.parent_id);
  EXPECT_EQ(root_element_id, converted_root_effect.element_id);

  const cc::EffectNode& converted_effect1 = *effect_tree.Node(2);
  EXPECT_EQ(converted_root_effect.id, converted_effect1.parent_id);
  EXPECT_FLOAT_EQ(0.5, converted_effect1.opacity);
  EXPECT_EQ(real_effect1->GetCompositorElementId(),
            converted_effect1.element_id);

  const cc::EffectNode& converted_effect2 = *effect_tree.Node(3);
  EXPECT_EQ(converted_effect1.id, converted_effect2.parent_id);
  EXPECT_FLOAT_EQ(0.3, converted_effect2.opacity);

  const cc::EffectNode& converted_effect3 = *effect_tree.Node(4);
  EXPECT_EQ(converted_root_effect.id, converted_effect3.parent_id);
  EXPECT_FLOAT_EQ(0.2, converted_effect3.opacity);

  EXPECT_EQ(converted_effect2.id, LayerAt(0)->effect_tree_index());
  EXPECT_EQ(converted_effect1.id, LayerAt(1)->effect_tree_index());
  EXPECT_EQ(converted_effect3.id, LayerAt(2)->effect_tree_index());
}

// Returns a RefCountedPropertyTreeState for composited scrolling paint
// properties with some arbitrary values.
static PropertyTreeState ScrollState1(
    const PropertyTreeState& parent_state = PropertyTreeState::Root(),
    CompositingReasons compositing_reasons =
        CompositingReason::kOverflowScrolling,
    MainThreadScrollingReasons main_thread_reasons = kNotScrollingOnMain) {
  return CreateScrollTranslationState(
      parent_state, 7, 9, gfx::Rect(3, 5, 11, 13), gfx::Size(27, 31),
      compositing_reasons, main_thread_reasons);
}

// Returns a RefCountedPropertyTreeState for composited scrolling paint
// properties with another set of arbitrary values.
static PropertyTreeState ScrollState2(
    const PropertyTreeState& parent_state = PropertyTreeState::Root(),
    CompositingReasons compositing_reasons =
        CompositingReason::kOverflowScrolling,
    MainThreadScrollingReasons main_thread_reasons = kNotScrollingOnMain) {
  return CreateScrollTranslationState(
      parent_state, 39, 31, gfx::Rect(0, 0, 19, 23), gfx::Size(27, 31),
      compositing_reasons, main_thread_reasons);
}

static void CheckCcScrollNode(const ScrollPaintPropertyNode& blink_scroll,
                              const cc::ScrollNode& cc_scroll) {
  EXPECT_EQ(blink_scroll.ContainerRect().size(), cc_scroll.container_bounds);
  EXPECT_EQ(blink_scroll.ContentsRect().size(), cc_scroll.bounds);
  EXPECT_EQ(blink_scroll.UserScrollableHorizontal(),
            cc_scroll.user_scrollable_horizontal);
  EXPECT_EQ(blink_scroll.UserScrollableVertical(),
            cc_scroll.user_scrollable_vertical);
  EXPECT_EQ(blink_scroll.GetCompositorElementId(), cc_scroll.element_id);
  EXPECT_EQ(blink_scroll.GetMainThreadRepaintReasons(),
            cc_scroll.main_thread_repaint_reasons);
}

TEST_P(PaintArtifactCompositorTest, OneScrollNodeComposited) {
  auto scroll_state = ScrollState1();
  auto& scroll = *scroll_state.Transform().ScrollNode();

  // Scroll node ElementIds are referenced by scroll animations.
  Update(TestPaintArtifact()
             .ScrollHitTestChunk(scroll_state)
             .Chunk(scroll_state)
             .RectDrawing(gfx::Rect(-110, 12, 170, 19), Color::kWhite)
             .Build());

  const cc::ScrollTree& scroll_tree = GetPropertyTrees().scroll_tree();
  // Node #0 reserved for null; #1 for root render surface.
  ASSERT_EQ(3u, scroll_tree.size());
  const cc::ScrollNode& scroll_node = *scroll_tree.Node(2);
  CheckCcScrollNode(scroll, scroll_node);
  EXPECT_EQ(1, scroll_node.parent_id);
  EXPECT_EQ(scroll_node.element_id, ScrollHitTestLayerAt(0)->element_id());
  EXPECT_EQ(scroll_node.id, ElementIdToScrollNodeIndex(scroll_node.element_id));

  const cc::TransformTree& transform_tree = GetPropertyTrees().transform_tree();
  const cc::TransformNode& transform_node =
      *transform_tree.Node(scroll_node.transform_id);
  EXPECT_TRUE(transform_node.local.IsIdentity());
  EXPECT_EQ(gfx::PointF(-7, -9), transform_node.scroll_offset);
  EXPECT_EQ(kNotScrollingOnMain, scroll_node.main_thread_repaint_reasons);

  auto* layer = NonScrollHitTestLayerAt(0);
  auto transform_node_index = layer->transform_tree_index();
  EXPECT_EQ(transform_node_index, transform_node.id);
  auto scroll_node_index = layer->scroll_tree_index();
  EXPECT_EQ(scroll_node_index, scroll_node.id);

  // The scrolling contents layer is clipped to the scrolling range.
  EXPECT_EQ(gfx::Size(27, 19), layer->bounds());
  EXPECT_EQ(gfx::Vector2dF(3, 12), layer->offset_to_transform_parent());
  EXPECT_THAT(layer->GetPicture(),
              Pointee(DrawsRectangle(gfx::RectF(0, 0, 57, 19), Color::kWhite)));

  auto* scroll_layer = ScrollHitTestLayerAt(0);
  // The scroll layer should be sized to the container bounds.
  // TODO(pdr): The container bounds will not include scrollbars but the scroll
  // layer should extend below scrollbars.
  EXPECT_EQ(gfx::Size(11, 13), scroll_layer->bounds());
  EXPECT_EQ(gfx::Vector2dF(3, 5), scroll_layer->offset_to_transform_parent());
  EXPECT_EQ(scroll_layer->scroll_tree_index(), scroll_node.id);

  std::optional<cc::TargetSnapAreaElementIds> targets;
  EXPECT_CALL(
      ScrollCallbacks(),
      DidCompositorScroll(scroll_node.element_id, gfx::PointF(1, 2), targets));
  GetPropertyTrees().scroll_tree_mutable().NotifyDidCompositorScroll(
      scroll_node.element_id, gfx::PointF(1, 2), targets);

  EXPECT_CALL(ScrollCallbacks(),
              DidChangeScrollbarsHidden(scroll_node.element_id, true));
  GetPropertyTrees().scroll_tree_mutable().NotifyDidChangeScrollbarsHidden(
      scroll_node.element_id, true);
}

TEST_P(PaintArtifactCompositorTest, OneScrollNodeNonComposited) {
  auto scroll_state =
      ScrollState1(PropertyTreeState::Root(), CompositingReason::kNone);
  Update(TestPaintArtifact().ScrollChunks(scroll_state).Build());
  // Non-composited scrollers still create cc transform and scroll nodes.
  EXPECT_EQ(3u, GetPropertyTrees().scroll_tree().size());
  EXPECT_EQ(3u, GetPropertyTrees().transform_tree().size());
  EXPECT_EQ(1u, LayerCount());
}

TEST_P(PaintArtifactCompositorTest, TransformUnderScrollNode) {
  auto scroll_state = ScrollState1();
  auto* transform =
      CreateTransform(scroll_state.Transform(), gfx::Transform(),
                      gfx::Point3F(), CompositingReason::kWillChangeTransform);

  TestPaintArtifact artifact;
  artifact.Chunk(scroll_state)
      .RectDrawing(gfx::Rect(-20, 4, 60, 8), Color::kBlack)
      .Chunk(*transform, c0(), e0())
      .RectDrawing(gfx::Rect(1, -30, 5, 70), Color::kWhite);
  Update(artifact.Build());

  const cc::ScrollTree& scroll_tree = GetPropertyTrees().scroll_tree();
  // Node #0 reserved for null; #1 for root render surface.
  ASSERT_EQ(3u, scroll_tree.size());
  const cc::ScrollNode& scroll_node = *scroll_tree.Node(2);

  // Both layers should refer to the same scroll tree node.
  const auto* layer0 = LayerAt(0);
  const auto* layer1 = LayerAt(1);
  EXPECT_EQ(scroll_node.id, layer0->scroll_tree_index());
  EXPECT_EQ(scroll_node.id, layer1->scroll_tree_index());

  // The scrolling layer is clipped to the scrollable range.
  EXPECT_EQ(gfx::Vector2dF(3, 5), layer0->offset_to_transform_parent());
  EXPECT_EQ(gfx::Size(27, 7), layer0->bounds());
  EXPECT_THAT(layer0->GetPicture(),
              Pointee(DrawsRectangle(gfx::RectF(0, 0, 37, 7), Color::kBlack)));

  // The layer under the transform without a scroll node is not clipped.
  EXPECT_EQ(gfx::Vector2dF(1, -30), layer1->offset_to_transform_parent());
  EXPECT_EQ(gfx::Size(5, 70), layer1->bounds());
  EXPECT_THAT(layer1->GetPicture(),
              Pointee(DrawsRectangle(gfx::RectF(0, 0, 5, 70), Color::kWhite)));

  const cc::TransformTree& transform_tree = GetPropertyTrees().transform_tree();
  const cc::TransformNode& scroll_transform_node =
      *transform_tree.Node(scroll_node.transform_id);
  // The layers have different transform nodes.
  EXPECT_EQ(scroll_transform_node.id, layer0->transform_tree_index());
  EXPECT_NE(scroll_transform_node.id, layer1->transform_tree_index());
}

TEST_P(PaintArtifactCompositorTest, NestedScrollNodes) {
  auto* effect = CreateOpacityEffect(e0(), 0.5);

  auto scroll_state_a = ScrollState1(
      PropertyTreeState(t0(), c0(), *effect),
      cc::MainThreadScrollingReason::kHasBackgroundAttachmentFixedObjects);
  auto& scroll_a = *scroll_state_a.Transform().ScrollNode();
  auto scroll_state_b = ScrollState2(scroll_state_a);
  auto& scroll_b = *scroll_state_b.Transform().ScrollNode();

  Update(TestPaintArtifact()
             .ScrollChunks(scroll_state_a)
             .ScrollChunks(scroll_state_b)
             .Build());

  const cc::ScrollTree& scroll_tree = GetPropertyTrees().scroll_tree();
  // Node #0 reserved for null; #1 for root render surface.
  ASSERT_EQ(4u, scroll_tree.size());
  const cc::ScrollNode& scroll_node_a = *scroll_tree.Node(2);
  CheckCcScrollNode(scroll_a, scroll_node_a);
  EXPECT_EQ(1, scroll_node_a.parent_id);
  EXPECT_EQ(scroll_node_a.element_id, ScrollHitTestLayerAt(0)->element_id());
  EXPECT_EQ(scroll_node_a.id,
            ElementIdToScrollNodeIndex(scroll_node_a.element_id));

  const cc::TransformTree& transform_tree = GetPropertyTrees().transform_tree();
  const cc::TransformNode& transform_node_a =
      *transform_tree.Node(scroll_node_a.transform_id);
  EXPECT_TRUE(transform_node_a.local.IsIdentity());
  EXPECT_EQ(gfx::PointF(-7, -9), transform_node_a.scroll_offset);

  const cc::ScrollNode& scroll_node_b = *scroll_tree.Node(3);
  CheckCcScrollNode(scroll_b, scroll_node_b);
  EXPECT_EQ(scroll_node_a.id, scroll_node_b.parent_id);
  EXPECT_EQ(scroll_node_b.element_id, ScrollHitTestLayerAt(1)->element_id());
  EXPECT_EQ(scroll_node_b.id,
            ElementIdToScrollNodeIndex(scroll_node_b.element_id));

  const cc::TransformNode& transform_node_b =
      *transform_tree.Node(scroll_node_b.transform_id);
  EXPECT_TRUE(transform_node_b.local.IsIdentity());
  EXPECT_EQ(gfx::PointF(-39, -31), transform_node_b.scroll_offset);
}

TEST_P(PaintArtifactCompositorTest, ScrollHitTestLayerOrder) {
  auto scroll_state = ScrollState1();
  auto& scroll = *scroll_state.Transform().ScrollNode();

  auto* transform =
      CreateTransform(scroll_state.Transform(), MakeTranslationMatrix(5, 5),
                      gfx::Point3F(), CompositingReason::k3DTransform);

  Update(TestPaintArtifact()
             .Chunk(scroll_state)
             .RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kWhite)
             .ScrollHitTestChunk(scroll_state)
             .Chunk(*transform, scroll_state.Clip(), scroll_state.Effect())
             .RectDrawing(gfx::Rect(0, 0, 50, 50), Color::kBlack)
             .Build());

  // The first content layer (background) should not have the scrolling element
  // id set.
  EXPECT_EQ(CompositorElementId(), NonScrollHitTestLayerAt(0)->element_id());

  // The scroll layer should be after the first content layer (background).
  EXPECT_LT(LayerIndex(NonScrollHitTestLayerAt(0)),
            LayerIndex(ScrollHitTestLayerAt(0)));
  const cc::ScrollTree& scroll_tree = GetPropertyTrees().scroll_tree();
  auto* scroll_node =
      scroll_tree.Node(ScrollHitTestLayerAt(0)->scroll_tree_index());
  ASSERT_EQ(scroll.GetCompositorElementId(), scroll_node->element_id);
  EXPECT_EQ(scroll.GetCompositorElementId(),
            ScrollHitTestLayerAt(0)->element_id());
  EXPECT_EQ(RuntimeEnabledFeatures::HitTestOpaquenessEnabled()
                ? cc::HitTestOpaqueness::kOpaque
                : cc::HitTestOpaqueness::kMixed,
            ScrollHitTestLayerAt(0)->hit_test_opaqueness());

  // The second content layer should appear after the first.
  EXPECT_LT(LayerIndex(ScrollHitTestLayerAt(0)),
            LayerIndex(NonScrollHitTestLayerAt(1)));
  EXPECT_EQ(CompositorElementId(), NonScrollHitTestLayerAt(1)->element_id());
}

TEST_P(PaintArtifactCompositorTest, NestedScrollableLayerOrder) {
  auto scroll_state_1 = ScrollState1();
  auto& scroll_1 = *scroll_state_1.Transform().ScrollNode();
  auto scroll_state_2 = ScrollState2(scroll_state_1);
  auto& scroll_2 = *scroll_state_2.Transform().ScrollNode();

  Update(TestPaintArtifact()
             .ScrollHitTestChunk(scroll_state_1)
             .ScrollHitTestChunk(scroll_state_2)
             .Chunk(scroll_state_2)
             .RectDrawing(gfx::Rect(0, 0, 50, 50), Color::kWhite)
             .Build());

  // Two scroll layers should be created for each scroll translation node.
  const cc::ScrollTree& scroll_tree = GetPropertyTrees().scroll_tree();
  const cc::ClipTree& clip_tree = GetPropertyTrees().clip_tree();
  auto* scroll_1_node =
      scroll_tree.Node(ScrollHitTestLayerAt(0)->scroll_tree_index());
  ASSERT_EQ(scroll_1.GetCompositorElementId(), scroll_1_node->element_id);
  auto* scroll_1_clip_node =
      clip_tree.Node(ScrollHitTestLayerAt(0)->clip_tree_index());
  // The scroll is not under clip_1.
  EXPECT_EQ(gfx::RectF(0, 0, 0, 0), scroll_1_clip_node->clip);

  auto* scroll_2_node =
      scroll_tree.Node(ScrollHitTestLayerAt(1)->scroll_tree_index());
  ASSERT_EQ(scroll_2.GetCompositorElementId(), scroll_2_node->element_id);
  auto* scroll_2_clip_node =
      clip_tree.Node(ScrollHitTestLayerAt(1)->clip_tree_index());
  // The scroll is not under clip_2 but is under the parent clip, clip_1.
  EXPECT_EQ(gfx::RectF(3, 5, 11, 13), scroll_2_clip_node->clip);

  // The first layer should be before the second scroll layer.
  EXPECT_LT(LayerIndex(ScrollHitTestLayerAt(0)),
            LayerIndex(ScrollHitTestLayerAt(1)));

  // The non-scrollable content layer should be after the second scroll layer.
  EXPECT_LT(LayerIndex(ScrollHitTestLayerAt(1)),
            LayerIndex(NonScrollHitTestLayerAt(0)));

  auto expected_hit_test_opaqueness =
      RuntimeEnabledFeatures::HitTestOpaquenessEnabled()
          ? cc::HitTestOpaqueness::kOpaque
          : cc::HitTestOpaqueness::kMixed;
  EXPECT_EQ(expected_hit_test_opaqueness,
            ScrollHitTestLayerAt(0)->hit_test_opaqueness());
  EXPECT_EQ(expected_hit_test_opaqueness,
            ScrollHitTestLayerAt(1)->hit_test_opaqueness());
}

TEST_P(PaintArtifactCompositorTest, AncestorScrollNodes) {
  auto scroll_state_a = ScrollState1();
  auto& scroll_a = *scroll_state_a.Transform().ScrollNode();
  auto scroll_state_b =
      ScrollState2(scroll_state_a, CompositingReason::kNone,
                   cc::MainThreadScrollingReason::kNotOpaqueForTextAndLCDText);
  auto& scroll_b = *scroll_state_b.Transform().ScrollNode();

  Update(TestPaintArtifact()
             .ScrollChunks(scroll_state_a)
             .ScrollChunks(scroll_state_b)
             .Build());

  const cc::ScrollTree& scroll_tree = GetPropertyTrees().scroll_tree();
  const cc::TransformTree& transform_tree = GetPropertyTrees().transform_tree();
  // Node #0 reserved for null; #1 for root render surface. #2 is for scroll_a.

  // Non-composited scrollers still create transform and scroll nodes.
  ASSERT_EQ(4u, scroll_tree.size());
  ASSERT_EQ(4u, transform_tree.size());

  const cc::ScrollNode& scroll_node_a = *scroll_tree.Node(2);
  EXPECT_EQ(1, scroll_node_a.parent_id);
  EXPECT_EQ(scroll_a.GetCompositorElementId(), scroll_node_a.element_id);
  EXPECT_EQ(scroll_node_a.id,
            ElementIdToScrollNodeIndex(scroll_node_a.element_id));
  // The first scrollable layer should be associated with scroll_a.
  EXPECT_EQ(scroll_node_a.element_id, ScrollHitTestLayerAt(0)->element_id());
  EXPECT_TRUE(scroll_node_a.is_composited);

  const cc::TransformNode& transform_node_a =
      *transform_tree.Node(scroll_node_a.transform_id);
  EXPECT_TRUE(transform_node_a.local.IsIdentity());
  EXPECT_EQ(gfx::PointF(-7, -9), transform_node_a.scroll_offset);
  EXPECT_EQ(gfx::PointF(-7, -9),
            scroll_tree.current_scroll_offset(scroll_node_a.element_id));

  const cc::ScrollNode& scroll_node_b = *scroll_tree.Node(3);
  EXPECT_EQ(scroll_node_a.id, scroll_node_b.parent_id);
  EXPECT_EQ(scroll_b.GetCompositorElementId(), scroll_node_b.element_id);
  EXPECT_EQ(scroll_node_b.id,
            ElementIdToScrollNodeIndex(scroll_node_b.element_id));
  EXPECT_FALSE(scroll_node_b.is_composited);

  const cc::TransformNode& transform_node_b =
      *transform_tree.Node(scroll_node_b.transform_id);
  EXPECT_TRUE(transform_node_b.local.IsIdentity());
  EXPECT_EQ(gfx::PointF(-39, -31), transform_node_b.scroll_offset);
  EXPECT_EQ(gfx::PointF(-39, -31),
            scroll_tree.current_scroll_offset(scroll_node_b.element_id));
}

TEST_P(PaintArtifactCompositorTest, AncestorNonCompositedScrollNode) {
  auto scroll_state_a =
      ScrollState1(PropertyTreeState::Root(), CompositingReason::kNone,
                   cc::MainThreadScrollingReason::kNotOpaqueForTextAndLCDText);
  auto& scroll_a = *scroll_state_a.Transform().ScrollNode();
  auto scroll_state_b = ScrollState2(scroll_state_a);
  auto& scroll_b = *scroll_state_b.Transform().ScrollNode();

  Update(TestPaintArtifact()
             .ScrollChunks(scroll_state_a)
             .ScrollChunks(scroll_state_b)
             .Build());

  const cc::ScrollTree& scroll_tree = GetPropertyTrees().scroll_tree();
  const cc::TransformTree& transform_tree = GetPropertyTrees().transform_tree();
  // Node #0 reserved for null; #1 for root render surface. #2 is for scroll_a
  // #3 for scroll_b.
  ASSERT_EQ(4u, scroll_tree.size());
  ASSERT_EQ(4u, transform_tree.size());

  const cc::ScrollNode& scroll_node_a = *scroll_tree.Node(2);
  EXPECT_EQ(1, scroll_node_a.parent_id);
  EXPECT_EQ(scroll_a.GetCompositorElementId(), scroll_node_a.element_id);
  EXPECT_EQ(scroll_node_a.id,
            ElementIdToScrollNodeIndex(scroll_node_a.element_id));
  EXPECT_FALSE(scroll_node_a.is_composited);

  const cc::TransformNode& transform_node_a =
      *transform_tree.Node(scroll_node_a.transform_id);
  EXPECT_TRUE(transform_node_a.local.IsIdentity());
  EXPECT_EQ(gfx::PointF(-7, -9), transform_node_a.scroll_offset);
  EXPECT_EQ(gfx::PointF(-7, -9),
            scroll_tree.current_scroll_offset(scroll_node_a.element_id));

  const cc::ScrollNode& scroll_node_b = *scroll_tree.Node(3);
  EXPECT_EQ(scroll_node_a.id, scroll_node_b.parent_id);
  EXPECT_EQ(scroll_b.GetCompositorElementId(), scroll_node_b.element_id);
  EXPECT_EQ(scroll_node_b.id,
            ElementIdToScrollNodeIndex(scroll_node_b.element_id));
  // The first scrollable layer should be associated with scroll_b.
  EXPECT_EQ(scroll_node_b.element_id, ScrollHitTestLayerAt(0)->element_id());
  EXPECT_TRUE(scroll_node_b.is_composited);

  const cc::TransformNode& transform_node_b =
      *transform_tree.Node(scroll_node_b.transform_id);
  EXPECT_TRUE(transform_node_b.local.IsIdentity());
  EXPECT_EQ(gfx::PointF(-39, -31), transform_node_b.scroll_offset);
  EXPECT_EQ(gfx::PointF(-39, -31),
            scroll_tree.current_scroll_offset(scroll_node_b.element_id));
}

// If a scroll node is encountered before its parent, ensure the parent scroll
// node is correctly created.
TEST_P(PaintArtifactCompositorTest, AncestorScrollNodesInversedOrder) {
  auto scroll_state_a = ScrollState1();
  auto& scroll_a = *scroll_state_a.Transform().ScrollNode();
  auto scroll_state_b = ScrollState2(scroll_state_a);
  auto& scroll_b = *scroll_state_b.Transform().ScrollNode();

  Update(TestPaintArtifact()
             .ScrollChunks(scroll_state_b)
             .ScrollChunks(scroll_state_a)
             .Build());

  const cc::ScrollTree& scroll_tree = GetPropertyTrees().scroll_tree();
  const cc::TransformTree& transform_tree = GetPropertyTrees().transform_tree();
  // Node #0 reserved for null; #1 for root render surface. #2 is for scroll_a.
  // #3 is for scroll_b.
  ASSERT_EQ(4u, scroll_tree.size());
  ASSERT_EQ(4u, transform_tree.size());

  const cc::ScrollNode& scroll_node_a = *scroll_tree.Node(2);
  EXPECT_EQ(1, scroll_node_a.parent_id);
  EXPECT_EQ(scroll_a.GetCompositorElementId(), scroll_node_a.element_id);
  EXPECT_EQ(scroll_node_a.id,
            ElementIdToScrollNodeIndex(scroll_node_a.element_id));
  // The second scrollable layer should be associated with scroll_a.
  EXPECT_EQ(scroll_node_a.element_id, ScrollHitTestLayerAt(1)->element_id());
  EXPECT_TRUE(scroll_node_a.is_composited);

  const cc::TransformNode& transform_node_a =
      *transform_tree.Node(scroll_node_a.transform_id);
  EXPECT_TRUE(transform_node_a.local.IsIdentity());
  EXPECT_EQ(gfx::PointF(-7, -9), transform_node_a.scroll_offset);
  EXPECT_EQ(gfx::PointF(-7, -9),
            scroll_tree.current_scroll_offset(scroll_node_a.element_id));

  const cc::ScrollNode& scroll_node_b = *scroll_tree.Node(3);
  EXPECT_EQ(scroll_node_a.id, scroll_node_b.parent_id);
  EXPECT_EQ(scroll_b.GetCompositorElementId(), scroll_node_b.element_id);
  EXPECT_EQ(scroll_node_b.id,
            ElementIdToScrollNodeIndex(scroll_node_b.element_id));
  // The first scrollable layer should be associated with scroll_b.
  EXPECT_EQ(scroll_node_b.element_id, ScrollHitTestLayerAt(0)->element_id());
  EXPECT_TRUE(scroll_node_b.is_composited);

  const cc::TransformNode& transform_node_b =
      *transform_tree.Node(scroll_node_b.transform_id);
  EXPECT_TRUE(transform_node_b.local.IsIdentity());
  EXPECT_EQ(gfx::PointF(-39, -31), transform_node_b.scroll_offset);
  EXPECT_EQ(gfx::PointF(-39, -31),
            scroll_tree.current_scroll_offset(scroll_node_b.element_id));
}

TEST_P(PaintArtifactCompositorTest,
       DifferentTransformTreeAndScrollTreeHierarchy) {
  auto scroll_state_a = ScrollState1();
  auto& scroll_a = *scroll_state_a.Transform().ScrollNode();
  auto scroll_state_b = ScrollState2(scroll_state_a);
  auto& scroll_b = *scroll_state_b.Transform().ScrollNode();
  // scroll_state_c's has root transform space, while the scroll parent is
  // scroll_b.
  auto scroll_state_c = CreateCompositedScrollTranslationState(
      PropertyTreeState::Root(), scroll_b, 11, 22, gfx::Rect(0, 0, 10, 20),
      gfx::Size(50, 60));
  auto& scroll_c = *scroll_state_c.Transform().ScrollNode();

  Update(TestPaintArtifact()
             .ScrollChunks(scroll_state_a)
             .ScrollChunks(scroll_state_b)
             .ScrollChunks(scroll_state_c)
             .Build());

  const cc::ScrollTree& scroll_tree = GetPropertyTrees().scroll_tree();
  const cc::TransformTree& transform_tree = GetPropertyTrees().transform_tree();
  // Node #0 reserved for null; #1 for root render surface. #2 is for scroll_a.
  // #3 is for scroll_b. #4 is for scroll_c.
  ASSERT_EQ(5u, scroll_tree.size());
  ASSERT_EQ(5u, transform_tree.size());

  const cc::ScrollNode& scroll_node_a = *scroll_tree.Node(2);
  EXPECT_EQ(1, scroll_node_a.parent_id);
  EXPECT_EQ(scroll_a.GetCompositorElementId(), scroll_node_a.element_id);
  EXPECT_EQ(scroll_node_a.id,
            ElementIdToScrollNodeIndex(scroll_node_a.element_id));
  EXPECT_EQ(scroll_node_a.element_id, ScrollHitTestLayerAt(0)->element_id());

  const cc::TransformNode& transform_node_a =
      *transform_tree.Node(scroll_node_a.transform_id);
  EXPECT_TRUE(transform_node_a.local.IsIdentity());
  EXPECT_EQ(gfx::PointF(-7, -9), transform_node_a.scroll_offset);
  EXPECT_EQ(gfx::PointF(-7, -9),
            scroll_tree.current_scroll_offset(scroll_node_a.element_id));

  const cc::ScrollNode& scroll_node_b = *scroll_tree.Node(3);
  EXPECT_EQ(scroll_node_a.id, scroll_node_b.parent_id);
  EXPECT_EQ(scroll_b.GetCompositorElementId(), scroll_node_b.element_id);
  EXPECT_EQ(scroll_node_b.id,
            ElementIdToScrollNodeIndex(scroll_node_b.element_id));
  EXPECT_EQ(scroll_node_b.element_id, ScrollHitTestLayerAt(1)->element_id());

  const cc::TransformNode& transform_node_b =
      *transform_tree.Node(scroll_node_b.transform_id);
  EXPECT_TRUE(transform_node_b.local.IsIdentity());
  EXPECT_EQ(gfx::PointF(-39, -31), transform_node_b.scroll_offset);
  EXPECT_EQ(gfx::PointF(-39, -31),
            scroll_tree.current_scroll_offset(scroll_node_b.element_id));

  const cc::ScrollNode& scroll_node_c = *scroll_tree.Node(4);
  EXPECT_EQ(scroll_node_b.id, scroll_node_c.parent_id);
  EXPECT_EQ(scroll_c.GetCompositorElementId(), scroll_node_c.element_id);
  EXPECT_EQ(scroll_node_c.id,
            ElementIdToScrollNodeIndex(scroll_node_c.element_id));
  EXPECT_EQ(scroll_node_c.element_id, ScrollHitTestLayerAt(2)->element_id());

  const cc::TransformNode& transform_node_c =
      *transform_tree.Node(scroll_node_c.transform_id);
  EXPECT_EQ(1, transform_node_c.parent_id);
  EXPECT_TRUE(transform_node_c.local.IsIdentity());
  EXPECT_EQ(gfx::PointF(-11, -22), transform_node_c.scroll_offset);
  EXPECT_EQ(gfx::PointF(-11, -22),
            scroll_tree.current_scroll_offset(scroll_node_c.element_id));
}

TEST_P(PaintArtifactCompositorTest,
       DifferentTransformTreeAndScrollTreeHierarchyInversedOrder) {
  auto scroll_state_a = ScrollState1();
  auto& scroll_a = *scroll_state_a.Transform().ScrollNode();
  auto scroll_state_b = ScrollState2(scroll_state_a);
  auto& scroll_b = *scroll_state_b.Transform().ScrollNode();
  // scroll_state_c's has root transform space, while the scroll parent is
  // scroll_b.
  auto scroll_state_c = CreateCompositedScrollTranslationState(
      PropertyTreeState::Root(), scroll_b, 11, 22, gfx::Rect(0, 0, 10, 20),
      gfx::Size(50, 60
```