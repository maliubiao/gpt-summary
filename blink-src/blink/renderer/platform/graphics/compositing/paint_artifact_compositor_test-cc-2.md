Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of a test file for the Chromium Blink engine.

The file `paint_artifact_compositor_test.cc` seems to be testing the `PaintArtifactCompositor`, a component responsible for translating paint artifacts (representing drawing instructions) into composited layers.

The provided code snippet focuses on testing different scenarios related to how scrollable content and fixed-position elements are handled during compositing. It also includes tests for how different paint chunks (sequences of drawing commands with associated properties like transforms, clips, and effects) are merged.

Here's a breakdown of the key functionalities demonstrated in this part of the code:

1. **Hierarchical Scrolling:** Tests how nested scrollable areas are represented in the compositor's scroll and transform trees.
2. **Fixed Position Elements:** Verifies the correct compositing of elements with fixed positioning within scrollable containers.
3. **Merging Paint Chunks:**  Explores various conditions under which consecutive paint chunks can be merged into a single drawing operation on a layer to optimize rendering. This involves considering factors like:
    - Simple consecutive drawings.
    - Applying clips.
    - Applying 2D and 3D transforms.
    - Applying transform origins.
    - Applying opacity effects.
    - Using property tree node aliases.
    - Handling clips and effects that need to be "pushed up" the property tree due to ancestor transforms.
4. **Compositor Element IDs:** Tests the association of compositor element IDs with transform and effect nodes, which is crucial for tracking and updating these properties during the rendering lifecycle.
5. **Non-Composited Masks:** Tests how simple masks (using `SkBlendMode::kDstIn`) are handled when they don't require separate composited layers.

Based on this analysis, I can formulate a summary.
这是 `blink/renderer/platform/graphics/compositing/paint_artifact_compositor_test.cc` 文件的一部分，主要功能是**测试 `PaintArtifactCompositor` 在处理滚动、固定定位元素以及优化绘制指令合并方面的逻辑**。

具体来说，这部分代码测试了以下功能：

1. **嵌套滚动容器的处理:**
   - **功能:**  测试当存在多个嵌套的可滚动容器时，`PaintArtifactCompositor` 如何构建和维护 `cc::ScrollTree` 和 `cc::TransformTree` 来正确表示这些滚动关系。
   - **与 JavaScript, HTML, CSS 的关系:** 这直接关系到网页中使用 `overflow: scroll` 或 `overflow: auto` 属性创建的滚动区域。当用户通过 JavaScript 修改滚动位置，或者浏览器根据 HTML 结构和 CSS 样式创建这些滚动容器时，`PaintArtifactCompositor` 需要准确地反映这些滚动状态。
   - **假设输入与输出:**  假设输入是定义了三个嵌套滚动容器（`scroll_a`, `scroll_b`, `scroll_c`）的 `TestPaintArtifact`，并且设置了各自的滚动偏移。输出是 `cc::ScrollTree` 和 `cc::TransformTree` 中对应节点的父子关系、元素 ID、变换信息以及当前的滚动偏移量。例如，`scroll_b` 的父节点是 `scroll_a` 对应的节点，它的滚动偏移量被正确记录。
   - **用户或编程常见错误:**  如果开发者在 CSS 中错误地设置了滚动容器的父子关系，或者 JavaScript 代码中错误地修改了滚动偏移，那么这里的测试会失败，因为它期望的滚动树结构和偏移量与实际生成的不符。

2. **固定定位元素在滚动容器中的处理:**
   - **功能:**  测试当固定定位元素 (`position: fixed`) 出现在可滚动容器中时，`PaintArtifactCompositor` 如何正确地处理其变换和层叠关系。
   - **与 JavaScript, HTML, CSS 的关系:**  这关系到 CSS 中的 `position: fixed` 属性。无论页面如何滚动，固定定位元素都应该相对于视口保持固定位置。`PaintArtifactCompositor` 需要确保这些元素被正确地提升到合适的合成层，避免受到滚动变换的影响。
   - **假设输入与输出:** 假设输入包含一个可滚动容器 `scroll_a` 和一个固定定位的子元素 `scroll_b`。输出是 `cc::ScrollTree` 和 `cc::TransformTree` 的结构，以及合成层的数量和属性。例如，固定定位的 `scroll_b` 的变换节点的父节点应该是根渲染表面，而不是 `scroll_a` 的变换节点。
   - **用户或编程常见错误:**  如果开发者错误地认为固定定位元素会跟随其父容器滚动，或者在 JavaScript 中错误地修改了固定定位元素的变换，那么测试会失败，因为它预期固定定位元素的变换是相对于视口的。

3. **非滚动子元素在固定定位元素下的处理:**
   - **功能:** 测试当一个非滚动的子元素位于一个固定定位的元素之下时，`PaintArtifactCompositor` 如何处理它们的层叠和变换关系。
   - **与 JavaScript, HTML, CSS 的关系:**  这涉及 CSS 中的 `position: fixed` 属性以及元素的层叠顺序。
   - **假设输入与输出:**  假设输入包含一个可滚动容器 `scroll_a`，其下有一个可滚动子容器 `scroll_b`，`scroll_b` 下有一个固定定位的元素，该固定定位元素下又有一个非滚动子元素。输出是合成层的数量和属性，以及 `cc::ScrollTree` 和 `cc::TransformTree` 的结构。例如，非滚动子元素的变换节点的父节点应该是固定定位元素的变换节点。

4. **合并简单的绘制块:**
   - **功能:** 测试当多个连续的绘制块 (`PaintChunk`) 没有不同的属性（如变换、裁剪、特效）时，`PaintArtifactCompositor` 是否能将它们合并到同一个合成层中进行绘制，以提高渲染效率。
   - **与 JavaScript, HTML, CSS 的关系:**  当 HTML 结构中存在多个相邻的、样式属性相同的元素时，或者 JavaScript 执行了多次连续的绘制操作时，会产生多个相似的绘制指令。合并这些指令可以减少合成层的数量和绘制开销。
   - **假设输入与输出:**  假设输入是包含两个只有矩形绘制指令的 `PaintChunk`。输出是只有一个合成层，并且该层的绘制指令包含了两个矩形的绘制操作。

5. **合并带裁剪的绘制块:**
   - **功能:** 测试当一个绘制块带有裁剪 (`ClipPaintPropertyNode`) 时，`PaintArtifactCompositor` 如何处理合并。只有在特定条件下，例如裁剪属性相同且父变换也相同时，才能合并。
   - **与 JavaScript, HTML, CSS 的关系:**  CSS 中的 `clip-path` 或 `overflow: hidden` 属性会产生裁剪。
   - **假设输入与输出:**  假设输入包含三个 `PaintChunk`，中间的 `PaintChunk` 应用了一个裁剪。输出是一个合成层，该层的绘制指令中，中间的矩形绘制操作会被裁剪。

6. **合并带 2D 变换的绘制块:**
   - **功能:** 测试当一个绘制块带有 2D 变换 (`TransformPaintPropertyNode`) 时，`PaintArtifactCompositor` 如何处理合并。只有在变换属性兼容的情况下才能合并。
   - **与 JavaScript, HTML, CSS 的关系:**  CSS 中的 `transform` 属性会产生 2D 或 3D 变换。
   - **假设输入与输出:**  假设输入包含三个 `PaintChunk`，中间的 `PaintChunk` 应用了一个 2D 变换。输出是一个合成层，该层的绘制指令中，中间的矩形绘制操作会应用该变换。

7. **合并带变换原点的绘制块:**
   - **功能:** 测试当一个绘制块带有变换原点 (`TransformPaintPropertyNode` 的 `transform_origin`) 时，`PaintArtifactCompositor` 如何处理合并。
   - **与 JavaScript, HTML, CSS 的关系:**  CSS 中的 `transform-origin` 属性定义了变换的中心点。
   - **假设输入与输出:**  假设输入包含三个 `PaintChunk`，中间的 `PaintChunk` 定义了变换原点。输出是一个合成层，该层的绘制指令中，中间的矩形绘制操作会根据指定的变换原点进行变换。

8. **合并带透明度效果的绘制块:**
   - **功能:** 测试当一个绘制块带有透明度效果 (`EffectPaintPropertyNode`，表示 opacity) 时，`PaintArtifactCompositor` 如何处理合并。
   - **与 JavaScript, HTML, CSS 的关系:**  CSS 中的 `opacity` 属性会产生透明度效果。
   - **假设输入与输出:**  假设输入包含三个 `PaintChunk`，中间的 `PaintChunk` 应用了透明度效果。输出是一个合成层，该层的绘制指令中，中间的矩形绘制操作会被应用指定的透明度。

9. **使用别名合并属性节点:**
   - **功能:** 测试当使用属性节点别名 (`TransformPaintPropertyNodeAlias`, `ClipPaintPropertyNodeAlias`, `EffectPaintPropertyNodeAlias`) 时，`PaintArtifactCompositor` 是否仍然能够正确地合并绘制块。这通常用于优化内存使用。
   - **与 JavaScript, HTML, CSS 的关系:**  虽然用户不会直接操作别名，但引擎内部会使用别名来共享相同的属性节点，例如多个元素具有相同的变换或透明度。
   - **假设输入与输出:**  假设输入包含使用别名的 `PaintChunk`。输出与不使用别名的情况类似，但引擎内部会对相同的属性节点进行共享。

10. **裁剪属性提升:**
    - **功能:**  测试当一个元素应用了裁剪，但其祖先元素存在变换时，裁剪属性如何被提升到变换的父级。
    - **与 JavaScript, HTML, CSS 的关系:**  当固定定位或绝对定位的元素需要超出滚动容器的边界绘制时，可能会出现这种情况。

11. **特效属性提升:**
    - **功能:**  测试当一个元素应用了特效（例如透明度），但其祖先元素存在变换时，特效属性如何被提升。

12. **裁剪和特效属性同时提升:**
    - **功能:**  测试当裁剪和特效属性都需要被提升时，`PaintArtifactCompositor` 的处理逻辑。

13. **根变换空间中的裁剪和特效:**
    - **功能:**  测试当裁剪和特效直接应用于根变换空间时，`PaintArtifactCompositor` 的处理。

14. **两个裁剪属性:**
    - **功能:**  测试当存在两个嵌套的裁剪属性时，`PaintArtifactCompositor` 如何计算最终的裁剪区域。

15. **两个变换属性之间存在裁剪:**
    - **功能:**  测试当存在两个变换属性，并且它们之间存在一个裁剪属性时，`PaintArtifactCompositor` 如何处理。

16. **不兼容变换导致的无法合并:**
    - **功能:**  测试当绘制块的变换属性不兼容时（例如具有 `CompositingReason::k3DTransform`），`PaintArtifactCompositor` 不会进行合并，而是创建独立的合成层。
    - **与 JavaScript, HTML, CSS 的关系:**  当元素应用了 3D 变换时，通常会创建独立的合成层以进行硬件加速。

17. **带有元素 ID 的变换属性节点:**
    - **功能:** 测试 `TransformPaintPropertyNode` 可以关联 `CompositorElementId`，用于在合成过程中唯一标识该变换节点。

18. **带有元素 ID 的特效属性节点:**
    - **功能:** 测试 `EffectPaintPropertyNode` 可以关联 `CompositorElementId`。

19. **不连续的带有元素 ID 的特效属性节点:**
    - **功能:** 测试当同一个带有元素 ID 的特效属性节点在不同的绘制块中使用时，`PaintArtifactCompositor` 会创建不同的合成层，但会正确地关联元素 ID。

20. **带有元素 ID 的特效属性节点及其别名:**
    - **功能:** 测试带有元素 ID 的特效属性节点及其别名也能被正确处理。

21. **非合成的简单遮罩:**
    - **功能:** 测试简单的遮罩效果（使用 `SkBlendMode::kDstIn`）在不需要创建独立合成层的情况下如何处理。
    - **与 JavaScript, HTML, CSS 的关系:**  `mix-blend-mode` 属性可以实现各种混合模式，包括遮罩效果。

总而言之，这部分测试代码的核心在于验证 `PaintArtifactCompositor` 能够正确地理解和转换 Blink 渲染引擎产生的绘制指令和相关的属性信息，最终生成高效且正确的合成层结构，以用于屏幕渲染。它覆盖了滚动、固定定位、变换、裁剪、透明度等多种重要的渲染场景，并关注了性能优化，例如绘制指令的合并。

Prompt: 
```
这是目录为blink/renderer/platform/graphics/compositing/paint_artifact_compositor_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共7部分，请归纳一下它的功能

"""
));
  auto& scroll_c = *scroll_state_c.Transform().ScrollNode();

  Update(TestPaintArtifact()
             .ScrollChunks(scroll_state_c)
             .ScrollChunks(scroll_state_b)
             .ScrollChunks(scroll_state_a)
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
  EXPECT_EQ(scroll_node_a.element_id, ScrollHitTestLayerAt(2)->element_id());

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
  EXPECT_EQ(scroll_node_c.element_id, ScrollHitTestLayerAt(0)->element_id());

  const cc::TransformNode& transform_node_c =
      *transform_tree.Node(scroll_node_c.transform_id);
  EXPECT_EQ(1, transform_node_c.parent_id);
  EXPECT_TRUE(transform_node_c.local.IsIdentity());
  EXPECT_EQ(gfx::PointF(-11, -22), transform_node_c.scroll_offset);
  EXPECT_EQ(gfx::PointF(-11, -22),
            scroll_tree.current_scroll_offset(scroll_node_c.element_id));
}

TEST_P(PaintArtifactCompositorTest, FixedPositionScrollState) {
  auto scroll_state_a = ScrollState1();
  auto& scroll_a = *scroll_state_a.Transform().ScrollNode();
  auto* fixed_transform = CreateFixedPositionTranslation(
      t0(), 100, 200, scroll_state_a.Transform());
  PropertyTreeState fixed_state(*fixed_transform, scroll_state_a.Clip(),
                                scroll_state_a.Effect());
  // scroll_state_b's has fixed transform space, while the scroll parent is
  // scroll_a.
  auto scroll_state_b = CreateCompositedScrollTranslationState(
      fixed_state, scroll_a, 11, 22, gfx::Rect(10, 20), gfx::Size(50, 60));
  auto& scroll_b = *scroll_state_b.Transform().ScrollNode();

  Update(TestPaintArtifact()
             .ScrollHitTestChunk(scroll_state_a)
             .Chunk(fixed_state)
             .RectDrawing(gfx::Rect(50, 100), Color::kBlack)
             .ScrollHitTestChunk(scroll_state_b)
             .Build());

  auto& scroll_tree = GetPropertyTrees().scroll_tree();
  auto& transform_tree = GetPropertyTrees().transform_tree();
  // Scroll node #0 reserved for null, #1 for root render surface, #2 is for
  // scroll_a, and #3 for scroll_b. Transform ids depend on the order in the
  // painted_scroll_translations_ HashMap so are not deterministic.
  ASSERT_EQ(4u, scroll_tree.size());
  ASSERT_EQ(5u, transform_tree.size());
  ASSERT_EQ(3u, LayerCount());

  auto* scroll_node_a = scroll_tree.Node(2);
  auto* layer_a = LayerAt(0);
  EXPECT_EQ(scroll_a.GetCompositorElementId(), scroll_node_a->element_id);
  EXPECT_EQ(1, scroll_node_a->parent_id);
  EXPECT_EQ(CcNodeId(scroll_state_a.Transform()), scroll_node_a->transform_id);
  EXPECT_EQ(2, layer_a->scroll_tree_index());
  EXPECT_EQ(1, layer_a->transform_tree_index());

  auto* fixed_layer = LayerAt(1);
  if (RuntimeEnabledFeatures::HitTestOpaquenessEnabled()) {
    EXPECT_EQ(2, fixed_layer->scroll_tree_index());
  } else {
    EXPECT_EQ(1, fixed_layer->scroll_tree_index());
  }
  EXPECT_EQ(CcNodeId(*fixed_transform), fixed_layer->transform_tree_index());
  auto* fixed_transform_node = transform_tree.Node(3);
  EXPECT_EQ(1, fixed_transform_node->parent_id);

  auto* scroll_node_b = scroll_tree.Node(3);
  auto* layer_b = LayerAt(2);
  EXPECT_EQ(2, scroll_node_b->parent_id);
  EXPECT_EQ(scroll_b.GetCompositorElementId(), scroll_node_b->element_id);
  EXPECT_EQ(CcNodeId(scroll_state_b.Transform()), scroll_node_b->transform_id);
  EXPECT_EQ(3, layer_b->scroll_tree_index());
  EXPECT_EQ(CcNodeId(*fixed_transform), layer_b->transform_tree_index());
}

TEST_P(PaintArtifactCompositorTest, NonScrollingChildUnderFixedPosition) {
  auto scroll_state_a = ScrollState1();
  auto& scroll_a = *scroll_state_a.Transform().ScrollNode();

  auto scroll_state_b = ScrollState2(scroll_state_a);
  auto& scroll_b = *scroll_state_b.Transform().ScrollNode();

  auto* fixed_transform = CreateFixedPositionTranslation(
      scroll_state_b.Transform(), 100, 200, scroll_state_a.Transform());
  PropertyTreeState fixed_state(*fixed_transform, scroll_state_a.Clip(),
                                scroll_state_a.Effect());
  // Use kActiveOpacityAnimation to avoid being decomposited with parent
  // transform.
  auto* child_transform = CreateTransform(
      *fixed_transform, MakeTranslationMatrix(50, 50),
      gfx::Point3F(100, 100, 0), CompositingReason::kActiveOpacityAnimation);
  // Use a different effect to get a different layer.
  auto* child_effect = CreateOpacityEffect(fixed_state.Effect(), 0.5f);
  PropertyTreeState child_state(*child_transform, fixed_state.Clip(),
                                *child_effect);

  Update(TestPaintArtifact()
             .ScrollHitTestChunk(scroll_state_a)
             .ScrollHitTestChunk(scroll_state_b)
             .Chunk(fixed_state)
             .RectDrawing(gfx::Rect(50, 100), Color::kBlack)
             .Chunk(child_state)
             .RectDrawing(gfx::Rect(100, 150), Color::kBlack)
             .Build());

  auto& scroll_tree = GetPropertyTrees().scroll_tree();
  auto& transform_tree = GetPropertyTrees().transform_tree();
  // Scroll node #0 reserved for null, #1 for root render surface, #2 is for
  // scroll_a, and #3 for scroll_b. Transform ids depend on the order in the
  // painted_scroll_translations_ HashMap so are not deterministic.
  ASSERT_EQ(4u, LayerCount());
  ASSERT_EQ(4u, scroll_tree.size());
  ASSERT_EQ(6u, transform_tree.size());

  auto* scroll_node_a = scroll_tree.Node(2);
  auto* layer_a = LayerAt(0);
  EXPECT_EQ(scroll_a.GetCompositorElementId(), scroll_node_a->element_id);
  EXPECT_EQ(1, scroll_node_a->parent_id);
  EXPECT_EQ(CcNodeId(scroll_state_a.Transform()), scroll_node_a->transform_id);
  EXPECT_EQ(2, layer_a->scroll_tree_index());
  EXPECT_EQ(1, layer_a->transform_tree_index());

  auto* scroll_node_b = scroll_tree.Node(3);
  auto* layer_b = LayerAt(1);
  EXPECT_EQ(scroll_b.GetCompositorElementId(), scroll_node_b->element_id);
  EXPECT_EQ(2, scroll_node_b->parent_id);
  EXPECT_EQ(CcNodeId(scroll_state_b.Transform()), scroll_node_b->transform_id);
  EXPECT_EQ(3, layer_b->scroll_tree_index());
  EXPECT_EQ(2, layer_b->transform_tree_index());

  auto* fixed_layer = LayerAt(2);
  if (RuntimeEnabledFeatures::HitTestOpaquenessEnabled()) {
    EXPECT_EQ(2, fixed_layer->scroll_tree_index());
  } else {
    EXPECT_EQ(3, fixed_layer->scroll_tree_index());
  }
  EXPECT_EQ(CcNodeId(*fixed_transform), fixed_layer->transform_tree_index());
  auto* fixed_transform_node = transform_tree.Node(4);
  EXPECT_EQ(3, fixed_transform_node->parent_id);

  auto* child_layer = LayerAt(3);
  EXPECT_EQ(child_layer->scroll_tree_index(), fixed_layer->scroll_tree_index());
  EXPECT_EQ(CcNodeId(*child_transform), child_layer->transform_tree_index());
  auto* child_transform_node = transform_tree.Node(5);
  EXPECT_EQ(4, child_transform_node->parent_id);
}

TEST_P(PaintArtifactCompositorTest, MergeSimpleChunks) {
  TestPaintArtifact test_artifact;
  test_artifact.Chunk().RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kWhite);
  test_artifact.Chunk().RectDrawing(gfx::Rect(0, 0, 200, 300), Color::kGray);

  auto& artifact = test_artifact.Build();
  ASSERT_EQ(2u, artifact.GetPaintChunks().size());
  Update(artifact);

  ASSERT_EQ(1u, LayerCount());
  {
    Vector<RectWithColor> rects_with_color;
    rects_with_color.push_back(
        RectWithColor(gfx::RectF(0, 0, 100, 100), Color::kWhite));
    rects_with_color.push_back(
        RectWithColor(gfx::RectF(0, 0, 200, 300), Color::kGray));

    const cc::Layer* layer = LayerAt(0);
    EXPECT_THAT(layer->GetPicture(),
                Pointee(DrawsRectangles(rects_with_color)));
  }
}

TEST_P(PaintArtifactCompositorTest, MergeClip) {
  auto* clip = CreateClip(c0(), t0(), FloatRoundedRect(10, 20, 50, 60));

  TestPaintArtifact test_artifact;
  test_artifact.Chunk().RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kWhite);
  test_artifact.Chunk(t0(), *clip, e0())
      .RectDrawing(gfx::Rect(0, 0, 200, 300), Color::kBlack);
  test_artifact.Chunk().RectDrawing(gfx::Rect(0, 0, 300, 400), Color::kGray);

  auto& artifact = test_artifact.Build();

  ASSERT_EQ(3u, artifact.GetPaintChunks().size());
  Update(artifact);
  ASSERT_EQ(1u, LayerCount());
  {
    Vector<RectWithColor> rects_with_color;
    rects_with_color.push_back(
        RectWithColor(gfx::RectF(0, 0, 100, 100), Color::kWhite));
    // Clip is applied to this PaintChunk.
    rects_with_color.push_back(
        RectWithColor(gfx::RectF(10, 20, 50, 60), Color::kBlack));
    rects_with_color.push_back(
        RectWithColor(gfx::RectF(0, 0, 300, 400), Color::kGray));

    const cc::Layer* layer = LayerAt(0);
    EXPECT_THAT(layer->GetPicture(),
                Pointee(DrawsRectangles(rects_with_color)));
  }
}

TEST_P(PaintArtifactCompositorTest, Merge2DTransform) {
  auto* transform = CreateTransform(t0(), MakeTranslationMatrix(50, 50),
                                    gfx::Point3F(100, 100, 0));

  TestPaintArtifact test_artifact;
  test_artifact.Chunk().RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kWhite);
  test_artifact.Chunk(*transform, c0(), e0())
      .RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kBlack);
  test_artifact.Chunk().RectDrawing(gfx::Rect(0, 0, 200, 300), Color::kGray);

  auto& artifact = test_artifact.Build();
  ASSERT_EQ(3u, artifact.GetPaintChunks().size());
  Update(artifact);

  ASSERT_EQ(1u, LayerCount());
  {
    Vector<RectWithColor> rects_with_color;
    rects_with_color.push_back(
        RectWithColor(gfx::RectF(0, 0, 100, 100), Color::kWhite));
    // Transform is applied to this PaintChunk.
    rects_with_color.push_back(
        RectWithColor(gfx::RectF(50, 50, 100, 100), Color::kBlack));
    rects_with_color.push_back(
        RectWithColor(gfx::RectF(0, 0, 200, 300), Color::kGray));

    const cc::Layer* layer = LayerAt(0);
    EXPECT_THAT(layer->GetPicture(),
                Pointee(DrawsRectangles(rects_with_color)));
  }
}

TEST_P(PaintArtifactCompositorTest, Merge2DTransformDirectAncestor) {
  auto* transform = CreateTransform(t0(), gfx::Transform(), gfx::Point3F(),
                                    CompositingReason::k3DTransform);
  auto* transform2 = CreateTransform(*transform, MakeTranslationMatrix(50, 50),
                                     gfx::Point3F(100, 100, 0));

  TestPaintArtifact test_artifact;
  test_artifact.Chunk(*transform, c0(), e0())
      .RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kWhite);
  // The second chunk can merge into the first because it has a descendant
  // state of the first's transform and no direct compositing reason.
  test_artifact.Chunk(*transform2, c0(), e0())
      .RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kBlack);

  auto& artifact = test_artifact.Build();
  ASSERT_EQ(2u, artifact.GetPaintChunks().size());
  Update(artifact);
  ASSERT_EQ(1u, LayerCount());
  {
    Vector<RectWithColor> rects_with_color;
    rects_with_color.push_back(
        RectWithColor(gfx::RectF(0, 0, 100, 100), Color::kWhite));
    // Transform is applied to this PaintChunk.
    rects_with_color.push_back(
        RectWithColor(gfx::RectF(50, 50, 100, 100), Color::kBlack));

    const cc::Layer* layer = LayerAt(0);
    EXPECT_THAT(layer->GetPicture(),
                Pointee(DrawsRectangles(rects_with_color)));
  }
}

TEST_P(PaintArtifactCompositorTest, MergeTransformOrigin) {
  auto* transform =
      CreateTransform(t0(), MakeRotationMatrix(45), gfx::Point3F(100, 100, 0));

  TestPaintArtifact test_artifact;
  test_artifact.Chunk().RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kWhite);
  test_artifact.Chunk(*transform, c0(), e0())
      .RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kBlack);
  test_artifact.Chunk().RectDrawing(gfx::Rect(0, 0, 200, 300), Color::kGray);

  auto& artifact = test_artifact.Build();
  ASSERT_EQ(3u, artifact.GetPaintChunks().size());
  Update(artifact);
  ASSERT_EQ(1u, LayerCount());
  {
    Vector<RectWithColor> rects_with_color;
    rects_with_color.push_back(
        RectWithColor(gfx::RectF(0, 42, 100, 100), Color::kWhite));
    // Transform is applied to this PaintChunk.
    rects_with_color.push_back(RectWithColor(
        gfx::RectF(29.2893, 0.578644, 141.421, 141.421), Color::kBlack));
    rects_with_color.push_back(
        RectWithColor(gfx::RectF(0, 42, 200, 300), Color::kGray));

    const cc::Layer* layer = LayerAt(0);
    EXPECT_THAT(layer->GetPicture(),
                Pointee(DrawsRectangles(rects_with_color)));
  }
}

TEST_P(PaintArtifactCompositorTest, MergeOpacity) {
  float opacity = 2.0 / 255.0;
  auto* effect = CreateOpacityEffect(e0(), opacity);

  TestPaintArtifact test_artifact;
  test_artifact.Chunk().RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kWhite);
  test_artifact.Chunk(t0(), c0(), *effect)
      .RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kBlack);
  test_artifact.Chunk().RectDrawing(gfx::Rect(0, 0, 200, 300), Color::kGray);

  auto& artifact = test_artifact.Build();
  ASSERT_EQ(3u, artifact.GetPaintChunks().size());
  Update(artifact);
  ASSERT_EQ(1u, LayerCount());
  {
    Vector<RectWithColor> rects_with_color;
    rects_with_color.push_back(
        RectWithColor(gfx::RectF(0, 0, 100, 100), Color::kWhite));
    // Transform is applied to this PaintChunk.
    Color semi_transparent_black = Color::FromSkColor4f({0, 0, 0, opacity});
    rects_with_color.push_back(
        RectWithColor(gfx::RectF(0, 0, 100, 100), semi_transparent_black));
    rects_with_color.push_back(
        RectWithColor(gfx::RectF(0, 0, 200, 300), Color::kGray));

    const cc::Layer* layer = LayerAt(0);
    EXPECT_THAT(layer->GetPicture(),
                Pointee(DrawsRectangles(rects_with_color)));
  }
}

TEST_P(PaintArtifactCompositorTest, MergeOpacityWithAlias) {
  float opacity = 2.0 / 255.0;
  auto* real_effect = CreateOpacityEffect(e0(), opacity);
  auto* effect = EffectPaintPropertyNodeAlias::Create(*real_effect);

  TestPaintArtifact test_artifact;
  test_artifact.Chunk().RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kWhite);
  test_artifact.Chunk(t0(), c0(), *effect)
      .RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kBlack);
  test_artifact.Chunk().RectDrawing(gfx::Rect(0, 0, 200, 300), Color::kGray);

  auto& artifact = test_artifact.Build();
  ASSERT_EQ(3u, artifact.GetPaintChunks().size());
  Update(artifact);
  ASSERT_EQ(1u, LayerCount());
  {
    Vector<RectWithColor> rects_with_color;
    rects_with_color.push_back(
        RectWithColor(gfx::RectF(0, 0, 100, 100), Color::kWhite));
    // Transform is applied to this PaintChunk.
    Color semi_transparent_black = Color::FromSkColor4f({0, 0, 0, opacity});
    rects_with_color.push_back(
        RectWithColor(gfx::RectF(0, 0, 100, 100), semi_transparent_black));
    rects_with_color.push_back(
        RectWithColor(gfx::RectF(0, 0, 200, 300), Color::kGray));

    const cc::Layer* layer = LayerAt(0);
    EXPECT_THAT(layer->GetPicture(),
                Pointee(DrawsRectangles(rects_with_color)));
  }
}

TEST_P(PaintArtifactCompositorTest, MergeNestedWithAlias) {
  // Tests merging of an opacity effect, inside of a clip, inside of a
  // transform.
  auto* real_transform = CreateTransform(t0(), MakeTranslationMatrix(50, 50),
                                         gfx::Point3F(100, 100, 0));
  auto* transform = TransformPaintPropertyNodeAlias::Create(*real_transform);
  auto* real_clip =
      CreateClip(c0(), *transform, FloatRoundedRect(10, 20, 50, 60));
  auto* clip = ClipPaintPropertyNodeAlias::Create(*real_clip);
  float opacity = 2.0 / 255.0;
  auto* real_effect = CreateOpacityEffect(e0(), *transform, clip, opacity);
  auto* effect = EffectPaintPropertyNodeAlias::Create(*real_effect);

  TestPaintArtifact test_artifact;
  test_artifact.Chunk().RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kWhite);
  test_artifact.Chunk(*transform, *clip, *effect)
      .RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kBlack);
  test_artifact.Chunk().RectDrawing(gfx::Rect(0, 0, 200, 300), Color::kGray);

  auto& artifact = test_artifact.Build();
  ASSERT_EQ(3u, artifact.GetPaintChunks().size());
  Update(artifact);
  ASSERT_EQ(1u, LayerCount());
  {
    Vector<RectWithColor> rects_with_color;
    rects_with_color.push_back(
        RectWithColor(gfx::RectF(0, 0, 100, 100), Color::kWhite));
    // Transform is applied to this PaintChunk.
    Color semi_transparent_black = Color::FromSkColor4f({0, 0, 0, opacity});
    rects_with_color.push_back(
        RectWithColor(gfx::RectF(60, 70, 50, 60), semi_transparent_black));
    rects_with_color.push_back(
        RectWithColor(gfx::RectF(0, 0, 200, 300), Color::kGray));

    const cc::Layer* layer = LayerAt(0);
    EXPECT_THAT(layer->GetPicture(),
                Pointee(DrawsRectangles(rects_with_color)));
  }
}

TEST_P(PaintArtifactCompositorTest, ClipPushedUp) {
  // Tests merging of an element which has a clipapplied to it,
  // but has an ancestor transform of them. This can happen for fixed-
  // or absolute-position elements which escape scroll transforms.
  auto* transform = CreateTransform(t0(), MakeTranslationMatrix(20, 25),
                                    gfx::Point3F(100, 100, 0));
  auto* transform2 = CreateTransform(*transform, MakeTranslationMatrix(20, 25),
                                     gfx::Point3F(100, 100, 0));
  auto* clip = CreateClip(c0(), *transform2, FloatRoundedRect(10, 20, 50, 60));

  TestPaintArtifact test_artifact;
  test_artifact.Chunk().RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kWhite);
  test_artifact.Chunk(t0(), *clip, e0())
      .RectDrawing(gfx::Rect(0, 0, 300, 400), Color::kBlack);
  test_artifact.Chunk().RectDrawing(gfx::Rect(0, 0, 200, 300), Color::kGray);

  auto& artifact = test_artifact.Build();
  ASSERT_EQ(3u, artifact.GetPaintChunks().size());
  Update(artifact);
  ASSERT_EQ(1u, LayerCount());
  {
    Vector<RectWithColor> rects_with_color;
    rects_with_color.push_back(
        RectWithColor(gfx::RectF(0, 0, 100, 100), Color::kWhite));
    // The two transforms (combined translation of (40, 50)) are applied here,
    // before clipping.
    rects_with_color.push_back(
        RectWithColor(gfx::RectF(50, 70, 50, 60), Color(Color::kBlack)));
    rects_with_color.push_back(
        RectWithColor(gfx::RectF(0, 0, 200, 300), Color::kGray));

    const cc::Layer* layer = LayerAt(0);
    EXPECT_THAT(layer->GetPicture(),
                Pointee(DrawsRectangles(rects_with_color)));
  }
}

TEST_P(PaintArtifactCompositorTest, EffectPushedUp) {
  // Tests merging of an element which has an effect applied to it,
  // but has an ancestor transform of them. This can happen for fixed-
  // or absolute-position elements which escape scroll transforms.

  auto* transform = CreateTransform(t0(), MakeTranslationMatrix(20, 25),
                                    gfx::Point3F(100, 100, 0));

  auto* transform2 = CreateTransform(*transform, MakeTranslationMatrix(20, 25),
                                     gfx::Point3F(100, 100, 0));

  float opacity = 2.0 / 255.0;
  auto* effect = CreateOpacityEffect(e0(), *transform2, &c0(), opacity);

  TestPaintArtifact test_artifact;
  test_artifact.Chunk().RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kWhite);
  test_artifact.Chunk(t0(), c0(), *effect)
      .RectDrawing(gfx::Rect(0, 0, 300, 400), Color::kBlack);
  test_artifact.Chunk().RectDrawing(gfx::Rect(0, 0, 200, 300), Color::kGray);

  auto& artifact = test_artifact.Build();
  ASSERT_EQ(3u, artifact.GetPaintChunks().size());
  Update(artifact);
  ASSERT_EQ(1u, LayerCount());
  {
    Vector<RectWithColor> rects_with_color;
    rects_with_color.push_back(
        RectWithColor(gfx::RectF(0, 0, 100, 100), Color::kWhite));
    Color semi_transparent_black = Color::FromSkColor4f({0, 0, 0, opacity});
    rects_with_color.push_back(
        RectWithColor(gfx::RectF(0, 0, 300, 400), semi_transparent_black));
    rects_with_color.push_back(
        RectWithColor(gfx::RectF(0, 0, 200, 300), Color::kGray));

    const cc::Layer* layer = LayerAt(0);
    EXPECT_THAT(layer->GetPicture(),
                Pointee(DrawsRectangles(rects_with_color)));
  }
}

TEST_P(PaintArtifactCompositorTest, EffectAndClipPushedUp) {
  // Tests merging of an element which has an effect applied to it,
  // but has an ancestor transform of them. This can happen for fixed-
  // or absolute-position elements which escape scroll transforms.
  auto* transform = CreateTransform(t0(), MakeTranslationMatrix(20, 25),
                                    gfx::Point3F(100, 100, 0));
  auto* transform2 = CreateTransform(*transform, MakeTranslationMatrix(20, 25),
                                     gfx::Point3F(100, 100, 0));
  auto* clip = CreateClip(c0(), *transform, FloatRoundedRect(10, 20, 50, 60));

  float opacity = 2.0 / 255.0;
  auto* effect = CreateOpacityEffect(e0(), *transform2, clip, opacity);

  TestPaintArtifact test_artifact;
  test_artifact.Chunk().RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kWhite);
  test_artifact.Chunk(t0(), *clip, *effect)
      .RectDrawing(gfx::Rect(0, 0, 300, 400), Color::kBlack);
  test_artifact.Chunk().RectDrawing(gfx::Rect(0, 0, 200, 300), Color::kGray);

  auto& artifact = test_artifact.Build();
  ASSERT_EQ(3u, artifact.GetPaintChunks().size());
  Update(artifact);
  ASSERT_EQ(1u, LayerCount());
  {
    Vector<RectWithColor> rects_with_color;
    rects_with_color.push_back(
        RectWithColor(gfx::RectF(0, 0, 100, 100), Color::kWhite));
    // The clip is under |transform| but not |transform2|, so only an adjustment
    // of (20, 25) occurs.
    Color semi_transparent_black = Color::FromSkColor4f({0, 0, 0, opacity});
    rects_with_color.push_back(
        RectWithColor(gfx::RectF(30, 45, 50, 60), semi_transparent_black));
    rects_with_color.push_back(
        RectWithColor(gfx::RectF(0, 0, 200, 300), Color::kGray));

    const cc::Layer* layer = LayerAt(0);
    EXPECT_THAT(layer->GetPicture(),
                Pointee(DrawsRectangles(rects_with_color)));
  }
}

TEST_P(PaintArtifactCompositorTest, ClipAndEffectNoTransform) {
  // Tests merging of an element which has a clip and effect in the root
  // transform space.
  auto* clip = CreateClip(c0(), t0(), FloatRoundedRect(10, 20, 50, 60));
  float opacity = 2.0 / 255.0;
  auto* effect = CreateOpacityEffect(e0(), t0(), clip, opacity);

  TestPaintArtifact test_artifact;
  test_artifact.Chunk().RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kWhite);
  test_artifact.Chunk(t0(), *clip, *effect)
      .RectDrawing(gfx::Rect(0, 0, 300, 400), Color::kBlack);
  test_artifact.Chunk().RectDrawing(gfx::Rect(0, 0, 200, 300), Color::kGray);

  auto& artifact = test_artifact.Build();
  ASSERT_EQ(3u, artifact.GetPaintChunks().size());
  Update(artifact);
  ASSERT_EQ(1u, LayerCount());
  {
    Vector<RectWithColor> rects_with_color;
    rects_with_color.push_back(
        RectWithColor(gfx::RectF(0, 0, 100, 100), Color::kWhite));
    Color semi_transparent_black = Color::FromSkColor4f({0, 0, 0, opacity});
    rects_with_color.push_back(
        RectWithColor(gfx::RectF(10, 20, 50, 60), semi_transparent_black));
    rects_with_color.push_back(
        RectWithColor(gfx::RectF(0, 0, 200, 300), Color::kGray));

    const cc::Layer* layer = LayerAt(0);
    EXPECT_THAT(layer->GetPicture(),
                Pointee(DrawsRectangles(rects_with_color)));
  }
}

TEST_P(PaintArtifactCompositorTest, TwoClips) {
  // Tests merging of an element which has two clips in the root
  // transform space.
  auto* clip = CreateClip(c0(), t0(), FloatRoundedRect(20, 30, 10, 20));
  auto* clip2 = CreateClip(*clip, t0(), FloatRoundedRect(10, 20, 50, 60));

  TestPaintArtifact test_artifact;
  test_artifact.Chunk().RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kWhite);
  test_artifact.Chunk(t0(), *clip2, e0())
      .RectDrawing(gfx::Rect(0, 0, 300, 400), Color::kBlack);
  test_artifact.Chunk().RectDrawing(gfx::Rect(0, 0, 200, 300), Color::kGray);

  auto& artifact = test_artifact.Build();
  ASSERT_EQ(3u, artifact.GetPaintChunks().size());
  Update(artifact);
  ASSERT_EQ(1u, LayerCount());
  {
    Vector<RectWithColor> rects_with_color;
    rects_with_color.push_back(
        RectWithColor(gfx::RectF(0, 0, 100, 100), Color::kWhite));
    // The interesction of the two clips is (20, 30, 10, 20).
    rects_with_color.push_back(
        RectWithColor(gfx::RectF(20, 30, 10, 20), Color(Color::kBlack)));
    rects_with_color.push_back(
        RectWithColor(gfx::RectF(0, 0, 200, 300), Color::kGray));

    const cc::Layer* layer = LayerAt(0);
    EXPECT_THAT(layer->GetPicture(),
                Pointee(DrawsRectangles(rects_with_color)));
  }
}

TEST_P(PaintArtifactCompositorTest, TwoTransformsClipBetween) {
  auto* transform = CreateTransform(t0(), MakeTranslationMatrix(20, 25),
                                    gfx::Point3F(100, 100, 0));
  auto* clip = CreateClip(c0(), t0(), FloatRoundedRect(0, 0, 50, 60));
  auto* transform2 = CreateTransform(*transform, MakeTranslationMatrix(20, 25),
                                     gfx::Point3F(100, 100, 0));
  TestPaintArtifact test_artifact;
  test_artifact.Chunk().RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kWhite);
  test_artifact.Chunk(*transform2, *clip, e0())
      .RectDrawing(gfx::Rect(0, 0, 300, 400), Color::kBlack);
  test_artifact.Chunk().RectDrawing(gfx::Rect(0, 0, 200, 300), Color::kGray);

  auto& artifact = test_artifact.Build();
  ASSERT_EQ(3u, artifact.GetPaintChunks().size());
  Update(artifact);
  ASSERT_EQ(1u, LayerCount());
  {
    Vector<RectWithColor> rects_with_color;
    rects_with_color.push_back(
        RectWithColor(gfx::RectF(0, 0, 100, 100), Color::kWhite));
    rects_with_color.push_back(
        RectWithColor(gfx::RectF(40, 50, 10, 10), Color(Color::kBlack)));
    rects_with_color.push_back(
        RectWithColor(gfx::RectF(0, 0, 200, 300), Color::kGray));
    const cc::Layer* layer = LayerAt(0);
    EXPECT_THAT(layer->GetPicture(),
                Pointee(DrawsRectangles(rects_with_color)));
  }
}

TEST_P(PaintArtifactCompositorTest, OverlapTransform) {
  auto* transform = CreateTransform(t0(), MakeTranslationMatrix(50, 50),
                                    gfx::Point3F(100, 100, 0),
                                    CompositingReason::k3DTransform);

  TestPaintArtifact test_artifact;
  test_artifact.Chunk().RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kWhite);
  test_artifact.Chunk(*transform, c0(), e0())
      .RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kBlack);
  test_artifact.Chunk().RectDrawing(gfx::Rect(0, 0, 200, 300), Color::kGray);

  auto& artifact = test_artifact.Build();
  ASSERT_EQ(3u, artifact.GetPaintChunks().size());
  Update(artifact);
  // The third paint chunk overlaps the second but can't merge due to
  // incompatible transform. The second paint chunk can't merge into the first
  // due to a direct compositing reason.
  ASSERT_EQ(3u, LayerCount());
}

EffectPaintPropertyNode* CreateSampleEffectNodeWithElementId() {
  EffectPaintPropertyNode::State state;
  state.local_transform_space = &t0();
  state.output_clip = &c0();
  state.opacity = 2.0 / 255.0;
  state.direct_compositing_reasons = CompositingReason::kActiveOpacityAnimation;
  state.compositor_element_id = CompositorElementIdFromUniqueObjectId(
      2, CompositorElementIdNamespace::kPrimaryEffect);
  return EffectPaintPropertyNode::Create(e0(), std::move(state));
}

TransformPaintPropertyNode* CreateSampleTransformNodeWithElementId() {
  TransformPaintPropertyNode::State state{{MakeRotationMatrix(90)}};
  state.direct_compositing_reasons = CompositingReason::k3DTransform;
  state.compositor_element_id = CompositorElementIdFromUniqueObjectId(
      3, CompositorElementIdNamespace::kPrimaryTransform);
  return TransformPaintPropertyNode::Create(t0(), std::move(state));
}

TEST_P(PaintArtifactCompositorTest, TransformWithElementId) {
  auto* transform = CreateSampleTransformNodeWithElementId();
  TestPaintArtifact artifact;
  artifact.Chunk(*transform, c0(), e0())
      .RectDrawing(gfx::Rect(100, 100, 200, 100), Color::kBlack);
  Update(artifact.Build());

  EXPECT_EQ(2,
            ElementIdToTransformNodeIndex(transform->GetCompositorElementId()));
}

TEST_P(PaintArtifactCompositorTest, EffectWithElementId) {
  auto* effect = CreateSampleEffectNodeWithElementId();
  TestPaintArtifact artifact;
  artifact.Chunk(t0(), c0(), *effect)
      .RectDrawing(gfx::Rect(100, 100, 200, 100), Color::kBlack);
  Update(artifact.Build());

  EXPECT_EQ(2, ElementIdToEffectNodeIndex(effect->GetCompositorElementId()));
}

TEST_P(PaintArtifactCompositorTest, NonContiguousEffectWithElementId) {
  auto* effect = CreateSampleEffectNodeWithElementId();
  TestPaintArtifact artifact;
  artifact.Chunk(t0(), c0(), *effect)
      .RectDrawing(gfx::Rect(100, 100, 200, 100), Color::kBlack)
      .Chunk(t0(), c0(), e0())
      .RectDrawing(gfx::Rect(100, 100, 300, 100), Color::kBlack)
      .Chunk(t0(), c0(), *effect)
      .RectDrawing(gfx::Rect(100, 100, 400, 100), Color::kBlack);
  Update(artifact.Build());

  ASSERT_EQ(3u, LayerCount());
  EXPECT_EQ(2, LayerAt(0)->effect_tree_index());
  cc::ElementId element_id = effect->GetCompositorElementId();
  EXPECT_EQ(element_id, GetPropertyTrees()
                            .effect_tree()
                            .Node(LayerAt(0)->effect_tree_index())
                            ->element_id);
  EXPECT_EQ(1, LayerAt(1)->effect_tree_index());
  EXPECT_EQ(3, LayerAt(2)->effect_tree_index());
  EXPECT_NE(element_id, GetPropertyTrees()
                            .effect_tree()
                            .Node(LayerAt(2)->effect_tree_index())
                            ->element_id);
}

TEST_P(PaintArtifactCompositorTest, EffectWithElementIdWithAlias) {
  auto* real_effect = CreateSampleEffectNodeWithElementId();
  auto* effect = EffectPaintPropertyNodeAlias::Create(*real_effect);
  TestPaintArtifact artifact;
  artifact.Chunk(t0(), c0(), *effect)
      .RectDrawing(gfx::Rect(100, 100, 200, 100), Color::kBlack);
  Update(artifact.Build());

  EXPECT_EQ(2,
            ElementIdToEffectNodeIndex(real_effect->GetCompositorElementId()));
}

TEST_P(PaintArtifactCompositorTest, NonCompositedSimpleMask) {
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
      .RectDrawing(gfx::Rect(100, 100, 200, 200), Color::kGray);
  artifact.Chunk(t0(), c0(), *masking)
      .RectDrawing(gfx::Rect(150, 150, 100, 100), Color::kWhite);
  Update(artifact.Build());
  ASSERT_EQ(1u, LayerCount());

  const cc::Layer* layer = LayerAt(0);
  EXPECT_THAT(*layer->GetPicture(),
              DrawsRectangles(Vector<RectWithColor>{
                  RectWithColor(gfx::RectF(0, 0, 200, 200), Color::kGray),
                  RectWithColor(gfx::RectF(50, 50, 100, 100), Color::kWhite)}));
  EXPECT_EQ(Translation(100, 
"""


```