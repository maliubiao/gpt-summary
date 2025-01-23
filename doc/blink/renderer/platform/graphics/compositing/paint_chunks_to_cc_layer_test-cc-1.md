Response:
The user is asking for a summary of the functionality of the provided C++ code snippet. This code snippet is part of a test file for the Blink rendering engine, specifically for the `PaintChunksToCcLayer` class.

Based on the test names and the operations being performed, the core functionality seems to be testing the conversion of paint chunks (which represent drawing operations and associated properties) into a `cc::PaintRecord`. The `cc::PaintRecord` is used by Chromium's Compositor to efficiently render graphics.

Here's a breakdown of the observed functionalities:

1. **Basic Conversion:** Tests the basic conversion of paint chunks into `cc::PaintRecord` operations like `DrawRecordOp`, `SaveOp`, `RestoreOp`.
2. **Transformations:** Tests how different transform property nodes (`TransformPaintPropertyNode`) are handled during the conversion, ensuring `ConcatOp` is used appropriately. It also checks for cases where identity transforms are optimized out.
3. **Clipping:** Tests how clip property nodes (`ClipPaintPropertyNode`) are converted into `ClipRectOp`. It considers scenarios with nested clips and how clips interact with transforms.
4. **Effects (Opacity):** Tests the conversion of effect property nodes (`EffectPaintPropertyNode`), specifically opacity, into `SaveLayerAlphaOp`. It also examines nested effects and how they interact with transforms.
5. **No-op Optimization:** Verifies that "no-op" property nodes (aliases that don't introduce any visual change) are correctly handled and don't lead to redundant drawing operations.
6. **Filter Effects:** Tests the conversion of filter effects (`FilterPaintPropertyNode`) into `SaveLayerOp` with appropriate `PaintFlags`. It also covers reference filters and how they interact with chunk bounds.
7. **Scrolling:** Tests the handling of scrolling content, specifically how `ScrollTranslationState` is converted into `ClipRectOp` and `TranslateOp` or `DrawScrollingContentsOp`. It appears to be testing a feature where scrolling content can be optimized into separate display item lists.
8. **Property Tree State:** The tests use `PropertyTreeState` to manage the hierarchy of transform, clip, and effect properties. The conversion process needs to correctly interpret this state.
9. **DisplayItemList Conversion:** Some tests use `ConvertInto` to convert paint chunks into a `cc::DisplayItemList` directly, which is another way of representing drawing operations for the compositor.

**Relationship to JavaScript, HTML, CSS:**

This code directly relates to how the visual representation of web pages (defined by HTML, styled by CSS, and potentially manipulated by JavaScript) is translated into rendering instructions.

*   **HTML:** The structure of the HTML document dictates the hierarchy of elements, which corresponds to the hierarchy of property tree nodes (transforms, clips, effects). For example, a nested `<div>` structure might lead to nested transform or clip property nodes.
*   **CSS:** CSS properties like `transform`, `clip-path`, `opacity`, `filter`, and `overflow: scroll` directly map to the paint property nodes being tested.
    *   `transform: scale(2)` would create a `TransformPaintPropertyNode` with a scaling matrix.
    *   `clip-path: rectangle(...)` would result in a `ClipPaintPropertyNode`.
    *   `opacity: 0.5` would lead to an `EffectPaintPropertyNode` representing opacity.
    *   `filter: blur(5px)` would create a `FilterPaintPropertyNode`.
    *   `overflow: scroll` would introduce a `ScrollTranslationState`.
*   **JavaScript:** JavaScript can dynamically modify the styles and structure of the HTML, which in turn affects the paint property tree. For instance, animating the `transform` property using JavaScript would lead to changes in the `TransformPaintPropertyNode` over time.

**Hypothetical Input and Output:**

*   **Input:** A `TestChunks` object containing a sequence of paint chunks representing drawing a red square inside a rotated and clipped `div`.
    *   Chunk 1: `t0()`, `c0()`, `e0()`, Draw a rectangle (initial state).
    *   Chunk 2: `CreateTransform(t0(), Rotate(45deg))`, `c0()`, `e0()`, Begin rotation.
    *   Chunk 3: `CreateTransform(t0(), Rotate(45deg))`, `CreateClip(...)`, `e0()`, Apply a clip.
    *   Chunk 4: `CreateTransform(t0(), Rotate(45deg))`, `CreateClip(...)`, `e0()`, Draw the red square.
*   **Output:** A `cc::PaintRecord` containing the following operations:
    *   `cc::DrawRecordOp` (for the initial rectangle)
    *   `cc::SaveOp`
    *   `cc::ConcatOp` (for the rotation transform)
    *   `cc::SaveOp`
    *   `cc::ClipRectOp` (for the clip)
    *   `cc::DrawRecordOp` (for the red square)
    *   `cc::RestoreOp` (for the clip)
    *   `cc::RestoreOp` (for the rotation transform)

**Common Usage Errors:**

*   **Incorrect Property Tree State:** Providing an incorrect `PropertyTreeState` during conversion can lead to incorrect transformations, clipping, and effects being applied. For instance, if the `PropertyTreeState` doesn't reflect the actual transform hierarchy, objects might be positioned or scaled incorrectly.
*   **Mismatched Save/Restore:**  Manually constructing paint operations (though less common in this context) requires careful matching of `SaveOp` and `RestoreOp`. Mismatches can lead to drawing operations being applied in the wrong context (e.g., outside a clip or with an unintended transform). This test code implicitly checks that `PaintChunksToCcLayer` handles these pairs correctly.
*   **Forgetting to finalize the DisplayItemList:** When using `ConvertInto` with `cc::DisplayItemList`, forgetting to call `Finalize()` before using the list can lead to incomplete or incorrect rendering.

**Summary of Functionality (Part 2):**

This part of the test file continues to verify the correct conversion of paint chunks into `cc::PaintRecord` and `cc::DisplayItemList` operations. It focuses on more complex scenarios involving:

*   **Interactions between different property types:** How transforms, clips, and effects are combined and applied when converting paint chunks.
*   **Optimization of no-op property nodes:** Ensuring that redundant or identity transformations and clips are efficiently handled and don't introduce unnecessary drawing operations.
*   **Handling of filter effects:**  Specifically, reference filters and how their geometry is calculated and applied, including cases with empty chunks.
*   **Support for scrolling content:**  Testing the generation of `DrawScrollingContentsOp` when converting chunks containing scrolling information, which optimizes rendering of scrollable areas.
*   **Conversion with a starting layer state:** Tests how the conversion behaves when provided with a non-root `PropertyTreeState`, simulating converting chunks within a specific layer's context.

这是 `blink/renderer/platform/graphics/compositing/paint_chunks_to_cc_layer_test.cc` 文件的一部分，主要功能是**测试 `PaintChunksToCcLayer::Convert` 方法将一系列 Paint Chunks 转换为 `cc::PaintRecord` 或 `cc::DisplayItemList` 的正确性**。

延续第一部分的分析，这部分继续测试了更复杂的场景，涵盖了以下功能点：

**1. 保持相同的属性树状态（ChunksSamePropertyTreeState）:**

*   **功能:** 测试当连续的 Paint Chunks 具有相同的变换和裁剪属性时，`PaintChunksToCcLayer::Convert` 是否能够正确地合并这些操作，避免不必要的 `SaveOp` 和 `RestoreOp`。
*   **假设输入:** 一组 Paint Chunks，其中一些具有相同的变换 (t1) 和裁剪 (c1) 属性。
*   **预期输出:** 生成的 `cc::PaintRecord` 会在共享相同属性的 Chunks 前后添加一次 `SaveOp` 和 `RestoreOp`，并在变换或裁剪属性发生变化时添加新的 `SaveOp` 和 `RestoreOp`。
*   **与 Javascript/HTML/CSS 的关系:**  当 HTML 元素具有相同的 CSS `transform` 和 `clip-path` 属性时，会产生这种场景。
    *   **例子:** 多个 `<div>` 元素应用了相同的 `transform: scale(2);` 和 `clip-path: rect(0, 0, 100px, 100px);`。

**2. 无操作变换的优化（NoOpForIdentityTransforms）:**

*   **功能:** 测试当 Paint Chunks 的变换属性是恒等变换（例如，平移 (0, 0)）时，`PaintChunksToCcLayer::Convert` 是否能够忽略这些无操作的变换，不生成对应的 `ConcatOp`。
*   **假设输入:** 一组 Paint Chunks，其中一些使用了恒等变换。
*   **预期输出:** 生成的 `cc::PaintRecord` 不会包含与恒等变换对应的 `ConcatOp`。只会为真正有意义的变换和裁剪生成操作。
*   **与 Javascript/HTML/CSS 的关系:** 当元素的 `transform` 属性被设置为 `translate(0, 0)` 或其他产生恒等矩阵的值时，会触发这种优化。

**3. 相同变换下的效果（EffectsWithSameTransform）和嵌套效果（NestedEffectsWithSameTransform）:**

*   **功能:** 测试当多个 Paint Chunks 具有相同的变换属性并应用了不同的效果（例如，不同的透明度）时，以及当效果嵌套时，`PaintChunksToCcLayer::Convert` 是否能够正确地生成 `SaveLayerAlphaOp`。
*   **假设输入:** 一组 Paint Chunks，它们具有相同的变换，但应用了不同的透明度效果。
*   **预期输出:** 生成的 `cc::PaintRecord` 会为每个不同的效果生成一个 `SaveLayerAlphaOp` 包裹对应的绘制操作。
*   **与 Javascript/HTML/CSS 的关系:** 当多个元素或同一个元素的不同绘制操作应用了不同的 `opacity` 属性，但共享相同的 `transform` 时，会出现这种情况。
    *   **例子:** 多个元素都设置了 `transform: scale(2);`，但分别设置了 `opacity: 0.1;` 和 `opacity: 0.2;`。

**4. No-op 变换节点处理（NoopTransformIsNotEmitted, OnlyNoopTransformIsNotEmitted, NoopTransformFirstThenBackToParent, ClipUndoesNoopTransform, EffectUndoesNoopTransform）:**

*   **功能:** 测试 `TransformPaintPropertyNodeAlias` (No-op 变换节点) 是否被正确处理。`PaintChunksToCcLayer::Convert` 应该能够识别并优化掉这些不产生实际变换效果的节点，除非后续的操作（例如裁剪或效果）依赖于其父节点的变换。
*   **假设输入:** 各种包含 `TransformPaintPropertyNodeAlias` 的 Paint Chunks 组合。
*   **预期输出:**  仅当 No-op 变换节点影响到后续裁剪或效果的计算时，才会生成对应的 `SaveOp` 和 `ConcatOp` (继承父节点的变换)。否则，这些节点会被忽略。
*   **与 Javascript/HTML/CSS 的关系:**  在内部实现中，可能存在创建这类 No-op 变换节点的情况，该测试确保渲染引擎能够正确优化它们。

**5. No-op 裁剪节点处理（NoopClipDoesNotEmitItems, EffectUndoesNoopClip）:**

*   **功能:** 测试 `ClipPaintPropertyNodeAlias` (No-op 裁剪节点) 的处理方式。类似于 No-op 变换节点，这些不产生实际裁剪效果的节点应该被优化掉，除非后续的效果依赖于其父节点的裁剪。
*   **假设输入:** 各种包含 `ClipPaintPropertyNodeAlias` 的 Paint Chunks 组合。
*   **预期输出:** 仅当 No-op 裁剪节点影响到后续效果的计算时，才会生成对应的 `SaveOp` 和 `ClipRectOp` (继承父节点的裁剪)。否则，这些节点会被忽略。
*   **与 Javascript/HTML/CSS 的关系:**  内部实现中可能创建这类 No-op 裁剪节点，该测试确保渲染引擎能够正确优化它们。

**6. No-op 效果节点处理（NoopEffectDoesNotEmitItems）:**

*   **功能:** 测试 `EffectPaintPropertyNodeAlias` (No-op 效果节点) 的处理方式。不产生实际视觉效果的节点应该被优化掉。
*   **假设输入:** 各种包含 `EffectPaintPropertyNodeAlias` 的 Paint Chunks 组合。
*   **预期输出:** 不会为 No-op 效果节点生成 `SaveLayerAlphaOp` 等操作。
*   **与 Javascript/HTML/CSS 的关系:**  内部实现中可能创建这类 No-op 效果节点，该测试确保渲染引擎能够正确优化它们。

**7. 空白 Chunk Rect 的处理（EmptyChunkRect）:**

*   **功能:** 测试当 Paint Chunk 的绘制区域为空时，是否仍然能够正确应用效果（例如，滤镜）。
*   **假设输入:** 一个绘制区域为空的 Paint Chunk，但应用了滤镜效果。
*   **预期输出:** 生成的 `cc::PaintRecord` 会包含 `SaveLayerOp` 和 `RestoreOp` 来应用滤镜效果，即使绘制区域为空。
*   **与 Javascript/HTML/CSS 的关系:**  即使元素没有实际内容，但应用了 `filter` 属性，仍然需要生成相应的渲染操作。

**8. 引用滤镜在空白 Chunk 上的处理（ReferenceFilterOnEmptyChunk）:**

*   **功能:** 测试当使用引用滤镜 (Reference Filter) 并且 Paint Chunk 为空时，滤镜的输出区域和视觉区域的计算是否正确。
*   **假设输入:** 一个空白的 Paint Chunk，应用了引用滤镜，并指定了引用区域和输出区域。
*   **预期输出:** 生成的 `cc::PaintRecord` 或 `cc::DisplayItemList` 会包含 `SaveLayerOp` 来应用滤镜，并且视觉区域会被正确计算。
*   **与 Javascript/HTML/CSS 的关系:** 当 CSS `filter` 属性使用 `url()` 引用 SVG 滤镜时，会用到引用滤镜。即使没有直接绘制内容，滤镜的输出仍然需要被渲染。

**9. 引用滤镜在有绘制项的 Chunk 上的处理（ReferenceFilterOnChunkWithDrawingDisplayItem）:**

*   **功能:** 测试当引用滤镜应用于包含实际绘制项的 Paint Chunk 时，视觉区域的计算是否正确，并且滤镜操作和绘制操作的顺序是否正确。
*   **假设输入:** 一个包含绘制项的 Paint Chunk，应用了引用滤镜。
*   **预期输出:** 生成的 `cc::PaintRecord` 或 `cc::DisplayItemList` 会先应用滤镜，然后绘制内容，并且视觉区域会被正确计算，包括滤镜的影响。
*   **与 Javascript/HTML/CSS 的关系:** 类似于上一点，当使用 SVG 滤镜时，需要确保滤镜效果正确应用于元素的内容。

**10. 滤镜裁剪扩展器在裁剪下的处理（FilterClipExpanderUnderClip）:**

*   **功能:** 测试当像素移动滤镜裁剪扩展器 (Pixel Moving Filter Clip Expander) 位于裁剪节点下时，渲染操作的顺序和正确性。这通常与处理模糊滤镜等需要扩展裁剪区域的效果有关。
*   **假设输入:** 一个位于裁剪节点下的 Paint Chunk，应用了需要裁剪扩展的滤镜。
*   **预期输出:** 生成的 `cc::PaintRecord` 会先进行裁剪，然后再应用滤镜效果。
*   **与 Javascript/HTML/CSS 的关系:**  当元素同时应用了 `clip-path` 和 `filter: blur(...)` 等需要扩展裁剪区域的滤镜时，需要保证渲染顺序的正确性。

**11. 滚动内容转换为 PaintRecord（ScrollingContentsToPaintRecord）和 DisplayItemList（ScrollingContentsIntoDisplayItemList, ScrollingContentsIntoDisplayItemListOverflowClipInLayerState, ScrollingContentsIntoDisplayItemListOverflowClipInLayerStateWithEffect, ScrollingContentsIntoDisplayItemListStartingFromNestedState, ScrollingContentsInterlacingNonScrollingIntoDisplayItemList）:**

*   **功能:** 测试如何将包含滚动信息的 Paint Chunk (`ScrollTranslationState`) 转换为 `cc::PaintRecord` 和 `cc::DisplayItemList`。特别是测试了 `DrawScrollingContentsOp` 的生成和使用，这是一种优化滚动性能的操作。
*   **假设输入:** 包含 `ScrollTranslationState` 的 Paint Chunks。
*   **预期输出:**
    *   转换为 `cc::PaintRecord` 时，会生成 `ClipRectOp` 和 `TranslateOp` 来模拟滚动效果。
    *   转换为 `cc::DisplayItemList` 并且启用了 `RasterInducingScrollEnabled` 特性时，会生成 `DrawScrollingContentsOp`，并将滚动内容放在一个单独的 `DisplayItemList` 中。
*   **与 Javascript/HTML/CSS 的关系:**  当 HTML 元素设置了 `overflow: scroll` 或 `overflow: auto` 并产生滚动条时，会生成 `ScrollTranslationState`。`DrawScrollingContentsOp` 能够将滚动区域的内容单独处理，以便更好地进行栅格化和合成。

**总结本部分的功能:**

这部分测试用例主要关注 `PaintChunksToCcLayer::Convert` 方法在处理更复杂的渲染场景时的正确性，特别是：

*   **各种属性节点组合和优化:**  深入测试了变换、裁剪和效果属性节点的不同组合方式，以及 No-op 节点的优化策略。
*   **滤镜效果的应用:** 详细测试了标准滤镜和引用滤镜在不同情况下的应用，包括空白区域和与绘制项的结合。
*   **滚动内容的转换：**  重点测试了如何将滚动信息有效地转换为渲染操作，并验证了 `DrawScrollingContentsOp` 的生成和使用，这对于优化滚动性能至关重要。

这些测试确保了 Blink 渲染引擎能够正确地将复杂的 CSS 样式和 HTML 结构转换为高效的渲染指令，从而保证网页的正确显示和流畅的用户体验。

### 提示词
```
这是目录为blink/renderer/platform/graphics/compositing/paint_chunks_to_cc_layer_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
/*antialias=*/true),  // <c7>
                  PaintOpIs<cc::DrawRecordOp>(),                   // <p0/>
                  PaintOpIs<cc::RestoreOp>(),                      // </c7>
                  PaintOpIs<cc::RestoreOp>(),                      // </c6>
                  PaintOpIs<cc::RestoreOp>(),                      // </c5>
                  PaintOpIs<cc::RestoreOp>(),                      // </c4>
                  PaintOpIs<cc::RestoreOp>()));  // </c1+c2+c3>
}

TEST_P(PaintChunksToCcLayerTest, ChunksSamePropertyTreeState) {
  auto* t1 = CreateTransform(t0(), MakeScaleMatrix(2));
  auto* t2 = CreateTransform(*t1, MakeScaleMatrix(3));
  auto* c1 = CreateClip(c0(), *t1, FloatRoundedRect(0, 0, 100, 100));

  TestChunks chunks;
  chunks.AddChunk(t0(), c0(), e0());
  chunks.AddChunk(*t1, c0(), e0());
  chunks.AddChunk(*t1, c0(), e0());
  chunks.AddChunk(*t1, *c1, e0());
  chunks.AddChunk(*t1, *c1, e0());
  chunks.AddChunk(*t2, *c1, e0());
  chunks.AddChunk(*t2, *c1, e0());

  PaintRecord output =
      PaintChunksToCcLayer::Convert(chunks.Build(), PropertyTreeState::Root());

  EXPECT_THAT(
      output,
      ElementsAre(PaintOpIs<cc::DrawRecordOp>(),                       // <p0/>
                  PaintOpIs<cc::SaveOp>(), PaintOpIs<cc::ConcatOp>(),  // <t1>
                  PaintOpIs<cc::DrawRecordOp>(),                       // <p1/>
                  PaintOpIs<cc::DrawRecordOp>(),                       // <p2/>
                  PaintOpIs<cc::SaveOp>(), PaintOpIs<cc::ClipRectOp>(),  // <c1>
                  PaintOpIs<cc::DrawRecordOp>(),                       // <p3/>
                  PaintOpIs<cc::DrawRecordOp>(),                       // <p4/>
                  PaintOpIs<cc::SaveOp>(), PaintOpIs<cc::ConcatOp>(),  // <t2>
                  PaintOpIs<cc::DrawRecordOp>(),                       // <p5/>
                  PaintOpIs<cc::DrawRecordOp>(),                       // <p6/>
                  PaintOpIs<cc::RestoreOp>(),                          // </t2>
                  PaintOpIs<cc::RestoreOp>(),                          // </c1>
                  PaintOpIs<cc::RestoreOp>()));                        // </t1>
}

TEST_P(PaintChunksToCcLayerTest, NoOpForIdentityTransforms) {
  auto* t1 = Create2DTranslation(t0(), 0, 0);
  auto* t2 = Create2DTranslation(*t1, 0, 0);
  auto* t3 = Create2DTranslation(*t2, 0, 0);
  auto* c1 = CreateClip(c0(), *t2, FloatRoundedRect(0, 0, 100, 100));
  auto* c2 = CreateClip(*c1, *t3, FloatRoundedRect(0, 0, 200, 50));

  TestChunks chunks;
  chunks.AddChunk(t0(), c0(), e0());
  chunks.AddChunk(*t1, c0(), e0());
  chunks.AddChunk(t0(), c0(), e0());
  chunks.AddChunk(*t1, c0(), e0());
  chunks.AddChunk(*t2, c0(), e0());
  chunks.AddChunk(*t1, c0(), e0());
  chunks.AddChunk(*t1, *c2, e0());

  auto output =
      PaintChunksToCcLayer::Convert(chunks.Build(), PropertyTreeState::Root());

  EXPECT_THAT(output,
              ElementsAre(PaintOpIs<cc::DrawRecordOp>(),  // <p0/>
                          PaintOpIs<cc::DrawRecordOp>(),  // <p1/>
                          PaintOpIs<cc::DrawRecordOp>(),  // <p2/>
                          PaintOpIs<cc::DrawRecordOp>(),  // <p3/>
                          PaintOpIs<cc::DrawRecordOp>(),  // <p4/>
                          PaintOpIs<cc::DrawRecordOp>(),  // <p5/>
                          PaintOpIs<cc::SaveOp>(),
                          PaintOpIs<cc::ClipRectOp>(),    // <c1+c2>
                          PaintOpIs<cc::DrawRecordOp>(),  // <p6/>
                          PaintOpIs<cc::RestoreOp>()));   // </c1+c2>
}

TEST_P(PaintChunksToCcLayerTest, EffectsWithSameTransform) {
  auto* t1 = CreateTransform(t0(), MakeScaleMatrix(2));
  auto* e1 = CreateOpacityEffect(e0(), *t1, &c0(), 0.1f);
  auto* e2 = CreateOpacityEffect(e0(), *t1, &c0(), 0.2f);

  TestChunks chunks;
  chunks.AddChunk(t0(), c0(), e0());
  chunks.AddChunk(*t1, c0(), *e1);
  chunks.AddChunk(*t1, c0(), *e2);

  auto output =
      PaintChunksToCcLayer::Convert(chunks.Build(), PropertyTreeState::Root());

  EXPECT_THAT(
      output,
      ElementsAre(PaintOpIs<cc::DrawRecordOp>(),                       // <p0/>
                  PaintOpIs<cc::SaveOp>(), PaintOpIs<cc::ConcatOp>(),  // <t1>
                  PaintOpIs<cc::SaveLayerAlphaOp>(),                   // <e1>
                  PaintOpIs<cc::DrawRecordOp>(),                       // <p1/>
                  PaintOpIs<cc::RestoreOp>(),                          // </e1>
                  PaintOpIs<cc::SaveLayerAlphaOp>(),                   // <e2>
                  PaintOpIs<cc::DrawRecordOp>(),                       // <p2>
                  PaintOpIs<cc::RestoreOp>(),                          // </e2>
                  PaintOpIs<cc::RestoreOp>()));                        // </t1>
}

TEST_P(PaintChunksToCcLayerTest, NestedEffectsWithSameTransform) {
  auto* t1 = CreateTransform(t0(), MakeScaleMatrix(2));
  auto* e1 = CreateOpacityEffect(e0(), *t1, &c0(), 0.1f);
  auto* e2 = CreateOpacityEffect(*e1, *t1, &c0(), 0.2f);

  TestChunks chunks;
  chunks.AddChunk(t0(), c0(), e0());
  chunks.AddChunk(*t1, c0(), *e1);
  chunks.AddChunk(*t1, c0(), *e2);

  auto output =
      PaintChunksToCcLayer::Convert(chunks.Build(), PropertyTreeState::Root());

  EXPECT_THAT(
      output,
      ElementsAre(PaintOpIs<cc::DrawRecordOp>(),                       // <p0/>
                  PaintOpIs<cc::SaveOp>(), PaintOpIs<cc::ConcatOp>(),  // <t1>
                  PaintOpIs<cc::SaveLayerAlphaOp>(),                   // <e1>
                  PaintOpIs<cc::DrawRecordOp>(),                       // <p1/>
                  PaintOpIs<cc::SaveLayerAlphaOp>(),                   // <e2>
                  PaintOpIs<cc::DrawRecordOp>(),                       // <p2>
                  PaintOpIs<cc::RestoreOp>(),                          // </e2>
                  PaintOpIs<cc::RestoreOp>(),                          // </e1>
                  PaintOpIs<cc::RestoreOp>()));                        // </t1>
}

TEST_P(PaintChunksToCcLayerTest, NoopTransformIsNotEmitted) {
  auto* t1 = CreateTransform(t0(), MakeScaleMatrix(2));
  auto* noop_t2 = TransformPaintPropertyNodeAlias::Create(*t1);
  auto* noop_t3 = TransformPaintPropertyNodeAlias::Create(*noop_t2);
  auto* t4 = CreateTransform(*noop_t3, MakeScaleMatrix(2));
  auto* noop_t5 = TransformPaintPropertyNodeAlias::Create(*t4);
  TestChunks chunks;
  chunks.AddChunk(t0(), c0(), e0());
  chunks.AddChunk(*t1, c0(), e0());
  chunks.AddChunk(*noop_t2, c0(), e0());
  chunks.AddChunk(*noop_t3, c0(), e0());
  chunks.AddChunk(*noop_t2, c0(), e0());
  chunks.AddChunk(*t4, c0(), e0());
  chunks.AddChunk(*noop_t5, c0(), e0());
  chunks.AddChunk(*t4, c0(), e0());

  auto output =
      PaintChunksToCcLayer::Convert(chunks.Build(), PropertyTreeState::Root());

  EXPECT_THAT(
      output,
      ElementsAre(PaintOpIs<cc::DrawRecordOp>(),  // draw with t0
                  PaintOpIs<cc::SaveOp>(), PaintOpIs<cc::ConcatOp>(),  // t1
                  PaintOpIs<cc::DrawRecordOp>(),  // draw with t1
                  PaintOpIs<cc::DrawRecordOp>(),  // draw with noop_t2
                  PaintOpIs<cc::DrawRecordOp>(),  // draw with noop_t3
                  PaintOpIs<cc::DrawRecordOp>(),  // draw with noop_t2
                  PaintOpIs<cc::RestoreOp>(),     // end t1
                  PaintOpIs<cc::SaveOp>(), PaintOpIs<cc::ConcatOp>(),  // t4
                  PaintOpIs<cc::DrawRecordOp>(),  // draw with t4
                  PaintOpIs<cc::DrawRecordOp>(),  // draw with noop_t5
                  PaintOpIs<cc::DrawRecordOp>(),  // draw with t4
                  PaintOpIs<cc::RestoreOp>()      // end t4
                  ));
}

TEST_P(PaintChunksToCcLayerTest, OnlyNoopTransformIsNotEmitted) {
  auto* noop_t1 = TransformPaintPropertyNodeAlias::Create(t0());
  auto* noop_t2 = TransformPaintPropertyNodeAlias::Create(*noop_t1);

  TestChunks chunks;
  chunks.AddChunk(t0(), c0(), e0());
  chunks.AddChunk(*noop_t1, c0(), e0());
  chunks.AddChunk(*noop_t2, c0(), e0());

  auto output =
      PaintChunksToCcLayer::Convert(chunks.Build(), PropertyTreeState::Root());

  EXPECT_THAT(output, ElementsAre(PaintOpIs<cc::DrawRecordOp>(),
                                  PaintOpIs<cc::DrawRecordOp>(),
                                  PaintOpIs<cc::DrawRecordOp>()));
}

TEST_P(PaintChunksToCcLayerTest, NoopTransformFirstThenBackToParent) {
  auto* t1 = CreateTransform(t0(), MakeScaleMatrix(2));
  auto* noop_t2 = TransformPaintPropertyNodeAlias::Create(*t1);

  TestChunks chunks;
  chunks.AddChunk(t0(), c0(), e0());
  chunks.AddChunk(*noop_t2, c0(), e0());
  chunks.AddChunk(*t1, c0(), e0());

  auto output =
      PaintChunksToCcLayer::Convert(chunks.Build(), PropertyTreeState::Root());

  EXPECT_THAT(output,
              ElementsAre(PaintOpIs<cc::DrawRecordOp>(),  // t0
                          PaintOpIs<cc::SaveOp>(),
                          PaintOpIs<cc::ConcatOp>(),      // t1 + noop_t2
                          PaintOpIs<cc::DrawRecordOp>(),  // draw with above
                          PaintOpIs<cc::DrawRecordOp>(),  // draw with just t1
                          PaintOpIs<cc::RestoreOp>()      // end t1
                          ));
}

TEST_P(PaintChunksToCcLayerTest, ClipUndoesNoopTransform) {
  auto* t1 = CreateTransform(t0(), MakeScaleMatrix(2));
  auto* noop_t2 = TransformPaintPropertyNodeAlias::Create(*t1);
  auto* c1 = CreateClip(c0(), *t1, FloatRoundedRect(0.f, 0.f, 1.f, 1.f));

  TestChunks chunks;
  chunks.AddChunk(t0(), c0(), e0());
  chunks.AddChunk(*noop_t2, c0(), e0());
  // The clip's local transform is t1, which is the parent of noop_t2.
  chunks.AddChunk(*noop_t2, *c1, e0());

  auto output =
      PaintChunksToCcLayer::Convert(chunks.Build(), PropertyTreeState::Root());

  EXPECT_THAT(
      output,
      ElementsAre(PaintOpIs<cc::DrawRecordOp>(),  // t0
                  PaintOpIs<cc::SaveOp>(),
                  PaintOpIs<cc::ConcatOp>(),  // t1 + noop_t2
                  PaintOpIs<cc::DrawRecordOp>(), PaintOpIs<cc::SaveOp>(),
                  PaintOpIs<cc::ClipRectOp>(),  // c1 (with t1 space)
                  PaintOpIs<cc::DrawRecordOp>(),
                  PaintOpIs<cc::RestoreOp>(),  // end c1
                  PaintOpIs<cc::RestoreOp>()   // end t1
                  ));
}

TEST_P(PaintChunksToCcLayerTest, EffectUndoesNoopTransform) {
  auto* t1 = CreateTransform(t0(), MakeScaleMatrix(2));
  auto* noop_t2 = TransformPaintPropertyNodeAlias::Create(*t1);
  auto* e1 = CreateOpacityEffect(e0(), *t1, &c0(), 0.5);

  TestChunks chunks;
  chunks.AddChunk(t0(), c0(), e0());
  chunks.AddChunk(*noop_t2, c0(), e0());
  // The effects's local transform is t1, which is the parent of noop_t2.
  chunks.AddChunk(*noop_t2, c0(), *e1);

  auto output =
      PaintChunksToCcLayer::Convert(chunks.Build(), PropertyTreeState::Root());

  EXPECT_THAT(output, ElementsAre(PaintOpIs<cc::DrawRecordOp>(),  // t0
                                  PaintOpIs<cc::SaveOp>(),
                                  PaintOpIs<cc::ConcatOp>(),  // t1 + noop_t2
                                  PaintOpIs<cc::DrawRecordOp>(),
                                  PaintOpIs<cc::SaveLayerAlphaOp>(),  // e1
                                  PaintOpIs<cc::DrawRecordOp>(),
                                  PaintOpIs<cc::RestoreOp>(),  // end e1
                                  PaintOpIs<cc::RestoreOp>()   // end t1
                                  ));
}

TEST_P(PaintChunksToCcLayerTest, NoopClipDoesNotEmitItems) {
  FloatRoundedRect clip_rect(0.f, 0.f, 1.f, 1.f);
  auto* c1 = CreateClip(c0(), t0(), clip_rect);
  auto* noop_c2 = ClipPaintPropertyNodeAlias::Create(*c1);
  auto* noop_c3 = ClipPaintPropertyNodeAlias::Create(*noop_c2);
  auto* c4 = CreateClip(*noop_c3, t0(), clip_rect);

  TestChunks chunks;
  chunks.AddChunk(t0(), c0(), e0());
  chunks.AddChunk(t0(), *c1, e0());
  chunks.AddChunk(t0(), *noop_c2, e0());
  chunks.AddChunk(t0(), *noop_c3, e0());
  chunks.AddChunk(t0(), *c4, e0());
  chunks.AddChunk(t0(), *noop_c2, e0());
  chunks.AddChunk(t0(), *c1, e0());

  auto output =
      PaintChunksToCcLayer::Convert(chunks.Build(), PropertyTreeState::Root());

  EXPECT_THAT(
      output,
      ElementsAre(PaintOpIs<cc::DrawRecordOp>(),                         // c0
                  PaintOpIs<cc::SaveOp>(), PaintOpIs<cc::ClipRectOp>(),  // c1
                  PaintOpIs<cc::DrawRecordOp>(),  // draw with c1
                  PaintOpIs<cc::DrawRecordOp>(),  // draw with noop_c2
                  PaintOpIs<cc::DrawRecordOp>(),  // draw_with noop_c3
                  PaintOpIs<cc::SaveOp>(), PaintOpIs<cc::ClipRectOp>(),  // c4
                  PaintOpIs<cc::DrawRecordOp>(),  // draw with c4
                  PaintOpIs<cc::RestoreOp>(),     // end c4
                  PaintOpIs<cc::DrawRecordOp>(),  // draw with noop_c2
                  PaintOpIs<cc::DrawRecordOp>(),  // draw with c1
                  PaintOpIs<cc::RestoreOp>()      // end noop_c2 (or c1)
                  ));
}

TEST_P(PaintChunksToCcLayerTest, EffectUndoesNoopClip) {
  FloatRoundedRect clip_rect(0.f, 0.f, 1.f, 1.f);
  auto* c1 = CreateClip(c0(), t0(), clip_rect);
  auto* noop_c2 = ClipPaintPropertyNodeAlias::Create(*c1);
  auto* e1 = CreateOpacityEffect(e0(), t0(), c1, 0.5);

  TestChunks chunks;
  chunks.AddChunk(t0(), *noop_c2, e0());
  chunks.AddChunk(t0(), *noop_c2, *e1);

  auto output =
      PaintChunksToCcLayer::Convert(chunks.Build(), PropertyTreeState::Root());

  EXPECT_THAT(output,
              ElementsAre(PaintOpIs<cc::SaveOp>(),
                          PaintOpIs<cc::ClipRectOp>(),    // noop_c2
                          PaintOpIs<cc::DrawRecordOp>(),  // draw with noop_c2
                          PaintOpIs<cc::SaveLayerAlphaOp>(),  // e1
                          PaintOpIs<cc::DrawRecordOp>(),      // draw with e1
                          PaintOpIs<cc::RestoreOp>(),         // end e1
                          PaintOpIs<cc::RestoreOp>()          // end noop_c2
                          ));
}

TEST_P(PaintChunksToCcLayerTest, NoopEffectDoesNotEmitItems) {
  auto* e1 = CreateOpacityEffect(e0(), 0.5f);
  auto* noop_e2 = EffectPaintPropertyNodeAlias::Create(*e1);
  auto* noop_e3 = EffectPaintPropertyNodeAlias::Create(*noop_e2);
  auto* e4 = CreateOpacityEffect(*noop_e3, 0.5f);

  TestChunks chunks;
  chunks.AddChunk(t0(), c0(), e0());
  chunks.AddChunk(t0(), c0(), *e1);
  chunks.AddChunk(t0(), c0(), *noop_e2);
  chunks.AddChunk(t0(), c0(), *noop_e3);
  chunks.AddChunk(t0(), c0(), *e4);
  chunks.AddChunk(t0(), c0(), *noop_e2);
  chunks.AddChunk(t0(), c0(), *e1);

  auto output =
      PaintChunksToCcLayer::Convert(chunks.Build(), PropertyTreeState::Root());

  EXPECT_THAT(output,
              ElementsAre(PaintOpIs<cc::DrawRecordOp>(),      // e0
                          PaintOpIs<cc::SaveLayerAlphaOp>(),  // e1
                          PaintOpIs<cc::DrawRecordOp>(),      // draw with e1
                          PaintOpIs<cc::DrawRecordOp>(),  // draw with noop_e2
                          PaintOpIs<cc::DrawRecordOp>(),  // draw_with noop_e3
                          PaintOpIs<cc::SaveLayerAlphaOp>(),  // e4
                          PaintOpIs<cc::DrawRecordOp>(),      // draw with e4
                          PaintOpIs<cc::RestoreOp>(),         // end e4
                          PaintOpIs<cc::DrawRecordOp>(),  // draw with noop_e2
                          PaintOpIs<cc::DrawRecordOp>(),  // draw with e1
                          PaintOpIs<cc::RestoreOp>()      // end noop_e2 (or e1)
                          ));
}

TEST_P(PaintChunksToCcLayerTest, EmptyChunkRect) {
  CompositorFilterOperations filter;
  filter.AppendBlurFilter(5);
  auto* e1 = CreateFilterEffect(e0(), t0(), &c0(), filter);
  TestChunks chunks;
  chunks.AddChunk(PaintRecord(), t0(), c0(), *e1, {0, 0, 0, 0});

  auto output =
      PaintChunksToCcLayer::Convert(chunks.Build(), PropertyTreeState::Root());

  cc::PaintFlags expected_flags;
  expected_flags.setImageFilter(cc::RenderSurfaceFilters::BuildImageFilter(
      filter.AsCcFilterOperations()));
  EXPECT_THAT(output, ElementsAre(PaintOpEq<cc::SaveLayerOp>(
                                      SkRect::MakeXYWH(0, 0, 0, 0),
                                      expected_flags),           // <e1>
                                  PaintOpIs<cc::RestoreOp>()));  // </e1>
}

static sk_sp<cc::PaintFilter> MakeFilter(gfx::RectF bounds) {
  PaintFilter::CropRect rect(gfx::RectFToSkRect(bounds));
  return sk_make_sp<ColorFilterPaintFilter>(
      cc::ColorFilter::MakeBlend(SkColors::kBlue, SkBlendMode::kSrc), nullptr,
      &rect);
}

TEST_P(PaintChunksToCcLayerTest, ReferenceFilterOnEmptyChunk) {
  CompositorFilterOperations filter;
  filter.AppendReferenceFilter(MakeFilter(gfx::RectF(12, 26, 93, 84)));
  filter.SetReferenceBox(gfx::RectF(11, 22, 33, 44));
  ASSERT_TRUE(filter.HasReferenceFilter());
  auto* e1 = CreateFilterEffect(e0(), t0(), &c0(), filter);
  TestChunks chunks;
  chunks.AddEmptyChunk(t0(), c0(), *e1, gfx::Rect(0, 0, 200, 300));

  auto cc_list = base::MakeRefCounted<cc::DisplayItemList>();
  PaintChunksToCcLayer::ConvertInto(chunks.Build(), PropertyTreeState::Root(),
                                    gfx::Vector2dF(5, 10), nullptr, *cc_list);
  ASSERT_EQ(5u, cc_list->TotalOpCount());
  // (7 16) is (12, 26) - layer_offset.
  gfx::Rect expected_visual_rect(7, 16, 93, 84);
  for (size_t i = 0; i < cc_list->TotalOpCount(); i++) {
    SCOPED_TRACE(testing::Message() << "Visual rect of op " << i);
    EXPECT_EQ(expected_visual_rect, cc_list->VisualRectForTesting(i));
  }

  auto output = cc_list->FinalizeAndReleaseAsRecordForTesting();

  cc::PaintFlags expected_flags;
  expected_flags.setImageFilter(cc::RenderSurfaceFilters::BuildImageFilter(
      filter.AsCcFilterOperations()));
  EXPECT_THAT(output, ElementsAre(PaintOpIs<cc::SaveOp>(),
                                  PaintOpIs<cc::TranslateOp>(),  // layer offset
                                  PaintOpEq<cc::SaveLayerOp>(
                                      SkRect::MakeXYWH(12, 26, 93, 84),
                                      expected_flags),         // <e1>
                                  PaintOpIs<cc::RestoreOp>(),  // </e1>
                                  PaintOpIs<cc::RestoreOp>()));
}

TEST_P(PaintChunksToCcLayerTest, ReferenceFilterOnChunkWithDrawingDisplayItem) {
  CompositorFilterOperations filter;
  filter.AppendReferenceFilter(MakeFilter(gfx::RectF(7, 16, 93, 84)));
  filter.SetReferenceBox(gfx::RectF(11, 22, 33, 44));
  ASSERT_TRUE(filter.HasReferenceFilter());
  auto* e1 = CreateFilterEffect(e0(), t0(), &c0(), filter);
  auto* clip_expander = CreatePixelMovingFilterClipExpander(c0(), *e1);
  TestChunks chunks;
  chunks.AddChunk(t0(), *clip_expander, *e1, gfx::Rect(5, 10, 200, 300),
                  gfx::Rect(10, 15, 20, 30));

  auto cc_list = base::MakeRefCounted<cc::DisplayItemList>();
  PaintChunksToCcLayer::ConvertInto(chunks.Build(), PropertyTreeState::Root(),
                                    gfx::Vector2dF(5, 10), nullptr, *cc_list);
  ASSERT_EQ(7u, cc_list->TotalOpCount());
  // This is the visual rect for all filter related paint operations, which is
  // the union of the draw record and the output bounds of the filter with empty
  // input in the layer's space. This is also the rect that the chunk bounds map
  // to via MapVisualRect since the filter does not actually use the source.
  gfx::Rect expected_filter_visual_rect(2, 6, 93, 84);
  // TotalOpCount() - 1 because the DrawRecord op has a sub operation.
  for (size_t i = 0; i < cc_list->TotalOpCount() - 1; i++) {
    SCOPED_TRACE(testing::Message() << "Visual rect of op " << i);
    EXPECT_EQ(expected_filter_visual_rect, cc_list->VisualRectForTesting(i));
  }

  auto output = cc_list->FinalizeAndReleaseAsRecordForTesting();

  cc::PaintFlags expected_flags;
  expected_flags.setImageFilter(cc::RenderSurfaceFilters::BuildImageFilter(
      filter.AsCcFilterOperations()));
  EXPECT_THAT(
      output,
      ElementsAre(PaintOpIs<cc::SaveOp>(),
                  PaintOpIs<cc::TranslateOp>(),  // layer offset
                  // The effect bounds are the union of the chunk's
                  // drawable_bounds and the output bounds of the filter
                  // with empty input in the filter's space.
                  PaintOpEq<cc::SaveLayerOp>(SkRect::MakeXYWH(7, 15, 93, 85),
                                             expected_flags),  // <e1>
                  PaintOpIs<cc::DrawRecordOp>(),  // the DrawingDisplayItem
                  PaintOpIs<cc::RestoreOp>(),     // </e1>
                  PaintOpIs<cc::RestoreOp>()));
}

TEST_P(PaintChunksToCcLayerTest, FilterClipExpanderUnderClip) {
  // This tests the situation of crbug.com/1350017.
  CompositorFilterOperations filter;
  filter.AppendBlurFilter(10);
  auto* e1 = CreateFilterEffect(e0(), t0(), &c0(), filter);
  auto* c1 = CreateClip(c0(), t0(), FloatRoundedRect(10, 20, 30, 40));
  auto* clip_expander = CreatePixelMovingFilterClipExpander(*c1, *e1);
  TestChunks chunks;
  chunks.AddChunk(t0(), *clip_expander, *e1, gfx::Rect(5, 10, 200, 300),
                  gfx::Rect(10, 15, 20, 30));

  auto output =
      PaintChunksToCcLayer::Convert(chunks.Build(), PropertyTreeState::Root());
  ASSERT_EQ(7u, output.total_op_count());
  EXPECT_THAT(
      output,
      ElementsAre(PaintOpIs<cc::SaveLayerOp>(),  // <e1>
                  PaintOpIs<cc::SaveOp>(),
                  PaintOpIs<cc::ClipRectOp>(),    // <c1>
                  PaintOpIs<cc::DrawRecordOp>(),  // the DrawingDisplayItem
                  PaintOpIs<cc::RestoreOp>(),     // </c1>
                  PaintOpIs<cc::RestoreOp>()));   // </e1>
}

TEST_P(PaintChunksToCcLayerTest, ScrollingContentsToPaintRecord) {
  auto scroll_state = CreateScrollTranslationState(
      PropertyTreeState::Root(), -50, -60, gfx::Rect(5, 5, 20, 30),
      gfx::Size(100, 200));
  TestChunks chunks;
  chunks.AddChunk(t0(), c0(), e0());
  chunks.AddChunk(scroll_state);
  chunks.AddChunk(t0(), c0(), e0());

  // Should not emit DrawScrollingContents when converting to PaintRecord.
  auto output =
      PaintChunksToCcLayer::Convert(chunks.Build(), PropertyTreeState::Root());
  EXPECT_THAT(
      output,
      ElementsAre(PaintOpIs<cc::DrawRecordOp>(),  // chunk 0
                  PaintOpIs<cc::SaveOp>(),
                  PaintOpEq<cc::ClipRectOp>(
                      SkRect::MakeXYWH(5, 5, 20, 30), SkClipOp::kIntersect,
                      /*antialias=*/true),  // <overflow-clip>
                  PaintOpIs<cc::SaveOp>(),
                  PaintOpEq<cc::TranslateOp>(-50, -60),  // <scroll-translation>
                  PaintOpIs<cc::DrawRecordOp>(),         // chuck 1
                  PaintOpIs<cc::RestoreOp>(),       // </scroll-translation>
                  PaintOpIs<cc::RestoreOp>(),       // </overflow-clip>
                  PaintOpIs<cc::DrawRecordOp>()));  // chuck 2
}

TEST_P(PaintChunksToCcLayerTest, ScrollingContentsIntoDisplayItemList) {
  auto scroll_state = CreateScrollTranslationState(
      PropertyTreeState::Root(), -50, -60, gfx::Rect(5, 5, 20, 30),
      gfx::Size(100, 200));
  TestChunks chunks;
  chunks.AddChunk(t0(), c0(), e0());
  chunks.AddChunk(scroll_state);
  chunks.AddChunk(t0(), c0(), e0());

  auto cc_list = base::MakeRefCounted<cc::DisplayItemList>();
  PaintChunksToCcLayer::ConvertInto(chunks.Build(), PropertyTreeState::Root(),
                                    gfx::Vector2dF(), nullptr, *cc_list);

  if (RuntimeEnabledFeatures::RasterInducingScrollEnabled()) {
    EXPECT_THAT(
        cc_list->paint_op_buffer(),
        ElementsAre(PaintOpIs<cc::DrawRecordOp>(),  // chunk 0
                    PaintOpIs<cc::SaveOp>(),
                    PaintOpEq<cc::ClipRectOp>(
                        SkRect::MakeXYWH(5, 5, 20, 30), SkClipOp::kIntersect,
                        /*antialias=*/true),  // <overflow-clip>
                    PaintOpIs<cc::DrawScrollingContentsOp>(),
                    PaintOpIs<cc::RestoreOp>(),       // </overflow-clip>
                    PaintOpIs<cc::DrawRecordOp>()));  // chunk 2
    EXPECT_EQ(
        gfx::Rect(5, 5, 20, 30),
        cc_list->raster_inducing_scrolls()
            .at(scroll_state.Transform().ScrollNode()->GetCompositorElementId())
            .visual_rect);
    const auto& scrolling_contents_op =
        static_cast<const cc::DrawScrollingContentsOp&>(
            cc_list->paint_op_buffer().GetOpAtForTesting(3));
    ASSERT_EQ(cc::PaintOpType::kDrawScrollingContents,
              scrolling_contents_op.GetType());
    EXPECT_THAT(scrolling_contents_op.display_item_list->paint_op_buffer(),
                ElementsAre(PaintOpIs<cc::DrawRecordOp>()));  // chunk 1
  } else {
    EXPECT_THAT(
        cc_list->paint_op_buffer(),
        ElementsAre(
            PaintOpIs<cc::DrawRecordOp>(),  // chunk 0
            PaintOpIs<cc::SaveOp>(),
            PaintOpEq<cc::ClipRectOp>(SkRect::MakeXYWH(5, 5, 20, 30),
                                      SkClipOp::kIntersect,
                                      /*antialias=*/true),  // <overflow-clip>
            PaintOpIs<cc::SaveOp>(),
            PaintOpEq<cc::TranslateOp>(-50, -60),  // <scroll-translation>
            PaintOpIs<cc::DrawRecordOp>(),         // chunk 1
            PaintOpIs<cc::RestoreOp>(),            // </scroll-translation>
            PaintOpIs<cc::RestoreOp>(),            // </overflow-clip>
            PaintOpIs<cc::DrawRecordOp>()));       // chunk 2
  }
}

TEST_P(PaintChunksToCcLayerTest,
       ScrollingContentsIntoDisplayItemListOverflowClipInLayerState) {
  if (!RuntimeEnabledFeatures::RasterInducingScrollEnabled()) {
    GTEST_SKIP();
  }

  auto scroll_state = CreateScrollTranslationState(
      PropertyTreeState::Root(), -50, -60, gfx::Rect(5, 5, 20, 30),
      gfx::Size(100, 200));
  TestChunks chunks;
  PropertyTreeState layer_state(t0(), scroll_state.Clip(), e0());
  chunks.AddChunk(layer_state);
  chunks.AddChunk(scroll_state);
  chunks.AddChunk(layer_state);

  auto cc_list = base::MakeRefCounted<cc::DisplayItemList>();
  PaintChunksToCcLayer::ConvertInto(chunks.Build(), layer_state,
                                    gfx::Vector2dF(), nullptr, *cc_list);

  EXPECT_THAT(cc_list->paint_op_buffer(),
              ElementsAre(PaintOpIs<cc::DrawRecordOp>(),  // chunk 0
                          PaintOpIs<cc::DrawScrollingContentsOp>(),
                          PaintOpIs<cc::DrawRecordOp>()));  // chunk 2
  const auto& scrolling_contents_op =
      static_cast<const cc::DrawScrollingContentsOp&>(
          cc_list->paint_op_buffer().GetOpAtForTesting(1));
  ASSERT_EQ(cc::PaintOpType::kDrawScrollingContents,
            scrolling_contents_op.GetType());
  EXPECT_THAT(scrolling_contents_op.display_item_list->paint_op_buffer(),
              ElementsAre(PaintOpIs<cc::DrawRecordOp>()));  // chunk 1
}

TEST_P(PaintChunksToCcLayerTest,
       ScrollingContentsIntoDisplayItemListOverflowClipInLayerStateWithEffect) {
  if (!RuntimeEnabledFeatures::RasterInducingScrollEnabled()) {
    GTEST_SKIP();
  }

  auto* effect = CreateOpacityEffect(e0(), t0(), nullptr, 0.5f);
  auto scroll_state = CreateScrollTranslationState(
      PropertyTreeState(t0(), c0(), *effect), -50, -60, gfx::Rect(5, 5, 20, 30),
      gfx::Size(100, 200));
  TestChunks chunks;
  PropertyTreeState layer_state(t0(), scroll_state.Clip(), e0());
  chunks.AddChunk(layer_state);
  chunks.AddChunk(scroll_state);
  chunks.AddChunk(layer_state);

  auto cc_list = base::MakeRefCounted<cc::DisplayItemList>();
  PaintChunksToCcLayer::ConvertInto(chunks.Build(), layer_state,
                                    gfx::Vector2dF(), nullptr, *cc_list);

  EXPECT_THAT(cc_list->paint_op_buffer(),
              ElementsAre(PaintOpIs<cc::DrawRecordOp>(),      // chunk 0
                          PaintOpIs<cc::SaveLayerAlphaOp>(),  // <effect>
                          PaintOpIs<cc::DrawScrollingContentsOp>(),
                          PaintOpIs<cc::RestoreOp>(),       // </effect>
                          PaintOpIs<cc::DrawRecordOp>()));  // chunk 2
  const auto& scrolling_contents_op =
      static_cast<const cc::DrawScrollingContentsOp&>(
          cc_list->paint_op_buffer().GetOpAtForTesting(2));
  ASSERT_EQ(cc::PaintOpType::kDrawScrollingContents,
            scrolling_contents_op.GetType());
  EXPECT_THAT(scrolling_contents_op.display_item_list->paint_op_buffer(),
              ElementsAre(PaintOpIs<cc::DrawRecordOp>()));  // chunk 1
}

TEST_P(PaintChunksToCcLayerTest,
       ScrollingContentsIntoDisplayItemListStartingFromNestedState) {
  if (!RuntimeEnabledFeatures::RasterInducingScrollEnabled()) {
    GTEST_SKIP();
  }

  auto scroll_state = CreateScrollTranslationState(
      PropertyTreeState::Root(), -50, -60, gfx::Rect(5, 5, 20, 30),
      gfx::Size(100, 200));
  auto* transform_under_scroll =
      CreateTransform(scroll_state.Transform(), MakeScaleMatrix(2));
  auto* effect_under_scroll =
      CreateOpacityEffect(scroll_state.Effect(), *transform_under_scroll,
                          &scroll_state.Clip(), 0.5f);
  auto* clip_under_scroll =
      CreateClip(scroll_state.Clip(), *transform_under_scroll,
                 FloatRoundedRect(0.f, 0.f, 1.f, 1.f));

  TestChunks chunks;
  chunks.AddChunk(t0(), c0(), e0());
  chunks.AddChunk(*transform_under_scroll, *clip_under_scroll,
                  *effect_under_scroll);
  chunks.AddChunk(scroll_state);
  chunks.AddChunk(t0(), c0(), e0());

  auto cc_list = base::MakeRefCounted<cc::DisplayItemList>();
  PaintChunksToCcLayer::ConvertInto(chunks.Build(), PropertyTreeState::Root(),
                                    gfx::Vector2dF(), nullptr, *cc_list);

  EXPECT_THAT(
      cc_list->paint_op_buffer(),
      ElementsAre(PaintOpIs<cc::DrawRecordOp>(),  // chunk 0
                  PaintOpIs<cc::SaveOp>(),
                  PaintOpEq<cc::ClipRectOp>(
                      SkRect::MakeXYWH(5, 5, 20, 30), SkClipOp::kIntersect,
                      /*antialias=*/true),  // <overflow-clip>
                  PaintOpIs<cc::DrawScrollingContentsOp>(),
                  PaintOpIs<cc::RestoreOp>(),       // </overflow-clip>
                  PaintOpIs<cc::DrawRecordOp>()));  // chunk 3
  EXPECT_EQ(
      gfx::Rect(5, 5, 20, 30),
      cc_list->raster_inducing_scrolls()
          .at(scroll_state.Transform().ScrollNode()->GetCompositorElementId())
          .visual_rect);
  const auto& scrolling_contents_op =
      static_cast<const cc::DrawScrollingContentsOp&>(
          cc_list->paint_op_buffer().GetOpAtForTesting(3));
  ASSERT_EQ(cc::PaintOpType::kDrawScrollingContents,
            scrolling_contents_op.GetType());
  EXPECT_THAT(
      scrolling_contents_op.display_item_list->paint_op_buffer(),
      ElementsAre(PaintOpIs<cc::SaveOp>(),
                  PaintOpEq<cc::ConcatOp>(
                      SkM44::Scale(2, 2)),  // <transform_under_scroll>
                  PaintOpIs<cc::SaveLayerAlphaOp>(),  // <effect_under_scroll>
                  PaintOpIs<cc::SaveOp>(),
                  PaintOpEq<cc::ClipRectOp>(
                      SkRect::MakeXYWH(0, 0, 1, 1), SkClipOp::kIntersect,
                      /*antialias=*/true),          // <clip_under_scroll>
                  PaintOpIs<cc::DrawRecordOp>(),    // chunk 1
                  PaintOpIs<cc::RestoreOp>(),       // </clip_under_scroll>
                  PaintOpIs<cc::RestoreOp>(),       // </effect_under_scroll>
                  PaintOpIs<cc::RestoreOp>(),       // </transform_under_scroll>
                  PaintOpIs<cc::DrawRecordOp>()));  // chunk 2
}

// This tests the following situation:
// <div id="scroller" style="width: 100px; height: 400px; overflow: scroll">
//   <div style="transform_under_scroll clip_under_scroll">
//     <div id="opacity" style="opacity: 0.5; height: 1000px">
//       Contained by scroller.
//       <div style="position: absolute">
//         Not contained by scroller.
//       </div>
//       Contained by scroller.
//     </div>
//   </div>
// </div>
TEST_P(PaintChunksToCcLayerTest,
       ScrollingContentsInterlacingNonScrollingIntoDisplayItemList) {
  if (!RuntimeEnabledFeatures::RasterInducingScrollEnabled()) {
    GTEST_SKIP();
  }

  auto scroll_state = CreateScrollTranslationState(
      PropertyTreeState::Root(), -50, -60, gfx::Rect(5, 5, 20, 30),
      gfx::Size(100, 200));
  auto* transform_under_scroll =
      CreateTransform(scroll_state.Transform(), MakeScaleMatrix(2));
  auto* clip_under_scroll =
      CreateClip(scroll_state.Clip(), *transform_under_scroll,
                 FloatRoundedRect(0.f, 0.f, 1.f, 1.f));
  // The effect has null OutputClip because some contents need to escape the
  // clip. This happens when an absolute-positioned element not containe
```