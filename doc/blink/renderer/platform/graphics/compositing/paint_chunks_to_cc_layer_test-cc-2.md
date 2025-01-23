Response:
The user wants to understand the functionality of the provided C++ code snippet, which is a test file for the `PaintChunksToCcLayer` class in the Chromium Blink engine. I need to analyze the code and explain its purpose. Specifically, the user asked for:

1. **General functionality:** What does this test file do?
2. **Relationship to web technologies:** Does it relate to JavaScript, HTML, or CSS? If so, how?
3. **Logical reasoning with examples:** Can I provide examples of input and expected output based on the code?
4. **Common usage errors:** Does the code highlight potential errors developers might make?
5. **Summary of functionality:**  A concise overview of the file's purpose (as it's the last part of a series).

Let's break down the code and address each point:

**1. General Functionality:**

The code is a series of unit tests (using the `TEST_P` macro from Google Test) for the `PaintChunksToCcLayer` class. This class is responsible for converting a sequence of "paint chunks" into a `cc::DisplayItemList`. A `cc::DisplayItemList` is a list of drawing operations that the Chromium Compositor uses to render web pages. The tests verify that `PaintChunksToCcLayer` correctly translates different configurations of paint chunks (which represent drawing commands and associated properties like transforms, clips, and effects) into the expected compositor drawing commands.

**2. Relationship to Web Technologies:**

Yes, this code is directly related to how HTML, CSS, and JavaScript are rendered in a web browser.

*   **HTML:** The structure of the HTML document influences the creation of paint chunks. Different HTML elements might generate different types of paint chunks.
*   **CSS:** CSS properties like `transform`, `clip-path`, `opacity`, `overflow`, and `background-attachment: fixed` directly map to the transform, clip, effect, and scrolling concepts being tested here. The tests simulate scenarios involving these CSS properties.
*   **JavaScript:** While this specific code doesn't directly involve JavaScript execution, JavaScript can dynamically modify the DOM and CSS, which in turn will affect the paint chunks generated and how they are converted into compositor commands. For instance, JavaScript could trigger scrolling, change element styles, or introduce animations, all of which would influence the behavior tested in this file.

**3. Logical Reasoning with Examples:**

Let's consider the `ScrollingContentsIntoDisplayItemListWithEffects` test.

*   **Hypothetical Input (Paint Chunks):** The test sets up a series of paint chunks. Imagine these represent drawing commands for different parts of a web page. Some chunks are associated with a scroller, have clipping applied, and are affected by an opacity effect. Other chunks are outside the scroller.
*   **Expected Output (cc::DisplayItemList):** The test then asserts that the resulting `cc::DisplayItemList` contains specific drawing operations (`cc::DrawRecordOp`, `cc::SaveLayerAlphaOp`, `cc::ClipRectOp`, `cc::DrawScrollingContentsOp`, etc.) in a particular order. It also checks that the scrolling content is rendered using `cc::DrawScrollingContentsOp`. The order and types of these operations are crucial for the compositor to render the content correctly, respecting the scrolling, clipping, and effects.

**4. Common Usage Errors:**

While this is test code and not directly used by developers writing web applications, understanding these tests can help identify potential issues in the rendering pipeline. For instance, if the `PaintChunksToCcLayer` logic is flawed:

*   **Incorrect application of transforms or clips:** This could lead to elements being positioned or clipped incorrectly on the screen.
*   **Issues with scrolling content:** Incorrect handling of scrolling containers might cause content to disappear, render at the wrong position, or not scroll smoothly. The tests specifically examine how scrolling content is wrapped in `DrawScrollingContentsOp`.
*   **Problems with effects:** Opacity, blur, or other visual effects might not be applied correctly or might impact performance if not handled efficiently in the compositor.

**5. Summary of Functionality:**

This part of the `paint_chunks_to_cc_layer_test.cc` file focuses on testing how `PaintChunksToCcLayer` handles complex scenarios involving:

*   **Scrolling:** Verifying the correct generation of `DrawScrollingContentsOp` for scrollable regions. This includes scenarios where effects are applied to scrolling content and nested scrolling.
*   **Nested Scrolling:** Ensuring correct handling of nested scrollable areas.
*   **Fixed Attachment Backgrounds:** Testing how fixed background images within scrolling containers are handled when the scroll container itself isn't composited.
*   **Region Capture:** Checking how "region capture" data (used for features like capturing specific parts of a web page) is associated with compositor layers.
*   **Non-Composited Backdrop Filters:** Testing the current behavior where non-composited backdrop filters are effectively ignored.

In essence, it's verifying the core logic of translating the results of the paint phase into the compositor's command stream, especially for advanced layout and rendering features like scrolling and effects.
这是 `blink/renderer/platform/graphics/compositing/paint_chunks_to_cc_layer_test.cc` 文件的最后一部分，其主要功能是**测试 `PaintChunksToCcLayer` 类在将 paint chunks 转换为 `cc::DisplayItemList` (用于 Chromium 合成器的绘图指令列表) 时的正确性，特别关注了复杂的合成场景，例如滚动、嵌套滚动、固定背景以及区域捕获等功能。**

作为第三部分，它延续了前两部分的测试，并涵盖了一些更特定的和可能更边缘的情况。

**与 JavaScript, HTML, CSS 的关系：**

这个测试文件直接关系到浏览器如何渲染 HTML、CSS 和 JavaScript 产生的视觉效果。

*   **HTML:**  HTML 结构定义了元素在页面上的布局和层叠关系，这些关系最终会影响 paint chunks 的生成。例如，一个 `<div>` 元素可能对应一个或多个 paint chunks。
*   **CSS:** CSS 样式属性（如 `transform`, `clip-path`, `opacity`, `overflow`, `background-attachment: fixed`, `backdrop-filter` 等）会直接影响 paint chunks 的属性，例如 transform、clip 和 effect。测试用例中创建的 `TransformState`, `ClipState`, `EffectState` 等就是模拟这些 CSS 属性。
*   **JavaScript:** JavaScript 可以动态地修改 DOM 和 CSS 样式，这会导致 paint chunks 的变化。虽然这个测试文件本身不执行 JavaScript 代码，但它验证了在这些动态变化发生后，渲染引擎能否正确地将 paint chunks 转换为合成器的指令。例如，JavaScript 滚动页面会导致测试中模拟的 `ScrollTranslationState` 的变化。

**功能归纳：**

这部分测试主要覆盖以下功能：

1. **带有 Effect 的滚动内容：** 测试当滚动容器内部的元素应用了视觉效果（例如透明度）时，`PaintChunksToCcLayer` 是否能正确生成合成器的绘图指令。它验证了 effect 是在滚动内容之上应用，并且对于未受 effect 影响的滚动内容会创建额外的 `DrawScrollingContentsOp`。

    *   **假设输入：** 一系列 paint chunks，其中一部分属于一个滚动容器，并且应用了一个透明度 effect。
    *   **预期输出：** `cc::DisplayItemList` 包含 `SaveLayerAlphaOp` 来应用透明度，以及一个或多个 `DrawScrollingContentsOp` 来绘制滚动内容，并正确处理 clip。

2. **嵌套的滚动内容：** 测试当存在多层嵌套的滚动容器时，`PaintChunksToCcLayer` 能否正确处理。它验证了每个滚动容器都会生成一个 `DrawScrollingContentsOp`，并且嵌套关系会在 `display_item_list` 中体现。

    *   **假设输入：** 一系列 paint chunks，表示两个嵌套的滚动容器以及一些其他内容。
    *   **预期输出：** `cc::DisplayItemList` 中包含两个 `DrawScrollingContentsOp`，外层滚动容器的 `display_item_list` 包含内层滚动容器的 `DrawScrollingContentsOp`。

3. **嵌套滚动内容从嵌套状态开始：**  测试从一个已有的滚动状态开始构建 paint chunks 时，嵌套滚动内容的处理是否正确。

    *   **假设输入：**  从一个已经定义的嵌套滚动状态开始添加 paint chunks，包括应用了 transform、clip 和 effect 的 chunk。
    *   **预期输出：** `cc::DisplayItemList` 正确地嵌套了 `DrawScrollingContentsOp`，并应用了 transform、clip 和 effect。

4. **非合成的固定背景：**  测试当带有 `background-attachment: fixed` 的元素在一个非合成的滚动容器内时，`PaintChunksToCcLayer` 的行为。在这种情况下，固定背景不会被提升为单独的合成层。

    *   **假设输入：**  一个带有固定背景的 paint chunk，以及一个非合成的滚动容器。
    *   **预期输出：** `cc::DisplayItemList` 中固定背景的绘制指令会出现在滚动内容的 `DrawScrollingContentsOp` 内部，并且会应用相应的 clip 和 translate。

5. **更新 Layer 属性中的区域捕获数据：**  测试 `UpdateLayerProperties` 函数是否能正确地将 paint chunk 中携带的区域捕获数据设置到 `cc::Layer` 对象上。它验证了捕获区域的边界信息被正确地存储。

    *   **假设输入：** 带有 `region_capture_data` 的 paint chunk。
    *   **预期输出：** `cc::Layer` 对象的 `capture_bounds()` 包含从 paint chunk 中提取的区域边界信息。

6. **区域捕获数据使用 Layer 偏移：** 测试在设置区域捕获数据时，是否考虑了 `cc::Layer` 的偏移量。这意味着捕获区域的坐标会根据 Layer 的偏移进行调整。

    *   **假设输入：** 带有 `region_capture_data` 的 paint chunk 和一个有偏移量的 `cc::Layer`。
    *   **预期输出：** `cc::Layer` 对象的 `capture_bounds()` 中存储的区域边界信息已经考虑了 Layer 的偏移。

7. **空区域捕获数据：** 测试当 paint chunk 中没有区域捕获数据时，`cc::Layer` 的 `capture_bounds()` 是否为空。

    *   **假设输入：** 没有 `region_capture_data` 的 paint chunk。
    *   **预期输出：** `cc::Layer` 对象的 `capture_bounds()` 为空。

8. **空的区域捕获边界：** 测试当 paint chunk 中的区域捕获数据包含空的边界时，`cc::Layer` 中存储的边界是否为空。

    *   **假设输入：** 带有空的区域捕获边界的 paint chunk。
    *   **预期输出：** `cc::Layer` 对象的 `capture_bounds()` 中存储的对应区域边界为空。

9. **多个 Chunk 的区域捕获数据：** 测试当多个 paint chunks 都包含区域捕获数据时，`cc::Layer` 能否合并并存储所有这些数据。

    *   **假设输入：** 多个带有不同区域捕获数据的 paint chunks。
    *   **预期输出：** `cc::Layer` 对象的 `capture_bounds()` 包含了所有 paint chunks 中的区域边界信息。

10. **非合成的 Backdrop Filter：** 测试当 backdrop filter 应用于一个非合成的元素时，`PaintChunksToCcLayer` 的行为。目前，非合成的 backdrop filter 会被忽略。

    *   **假设输入：** 应用了 backdrop filter 的 paint chunk。
    *   **预期输出：**  `cc::DisplayItemList` 中不会包含专门用于 backdrop filter 合成的指令，而是像普通的绘制操作一样处理。

**用户或编程常见的使用错误示例：**

虽然这是一个测试文件，但它可以帮助理解在实现渲染逻辑时可能出现的错误：

*   **不正确的滚动内容处理：** 如果 `PaintChunksToCcLayer` 没有正确识别滚动容器并生成 `DrawScrollingContentsOp`，可能会导致滚动内容无法正确显示或无法滚动。例如，没有将滚动容器内的内容放到 `DrawScrollingContentsOp` 中，可能会导致 transform 或 clip 没有正确应用到滚动内容上。
*   **Effect 应用顺序错误：** 如果 effect（如透明度）没有在滚动内容之上应用，可能会导致视觉效果不符合预期。例如，透明度 effect 应用在 clip 之前，可能会导致 clip 后的内容透明度也受到影响。
*   **嵌套滚动处理不当：** 如果没有正确处理嵌套滚动，可能会导致内部滚动容器的滚动行为异常或无法滚动。
*   **区域捕获数据处理错误：** 如果在设置区域捕获数据时没有考虑 Layer 的偏移，可能会导致捕获的区域不正确。

总而言之，这部分测试着重于验证 `PaintChunksToCcLayer` 在处理复杂合成场景时的正确性，确保渲染引擎能够准确地将 paint chunks 转换为合成器能够理解的绘图指令，从而保证网页的正确渲染和交互。

### 提示词
```
这是目录为blink/renderer/platform/graphics/compositing/paint_chunks_to_cc_layer_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
d by
  // the scroller is under an effect under the scroller.
  auto* effect_under_scroll =
      CreateOpacityEffect(e0(), *transform_under_scroll, nullptr, 0.5f);

  TestChunks chunks;
  chunks.AddChunk(t0(), c0(), e0());
  // Contained by scroller.
  chunks.AddChunk(*transform_under_scroll, *clip_under_scroll,
                  *effect_under_scroll);
  // Not contained by scroller.
  chunks.AddChunk(t0(), c0(), *effect_under_scroll);
  // Contained by scroller.
  chunks.AddChunk(*transform_under_scroll, *clip_under_scroll, e0());
  chunks.AddChunk(t0(), c0(), e0());

  auto cc_list = base::MakeRefCounted<cc::DisplayItemList>();
  PaintChunksToCcLayer::ConvertInto(chunks.Build(), PropertyTreeState::Root(),
                                    gfx::Vector2dF(), nullptr, *cc_list);

  EXPECT_THAT(
      cc_list->paint_op_buffer(),
      ElementsAre(
          PaintOpIs<cc::DrawRecordOp>(),      // chunk 0
                                              // The effect is applied above the
                                              // DrawScrollingContentsOp.
          PaintOpIs<cc::SaveLayerAlphaOp>(),  // <effect>
          PaintOpIs<cc::SaveOp>(),
          PaintOpEq<cc::ClipRectOp>(SkRect::MakeXYWH(5, 5, 20, 30),
                                    SkClipOp::kIntersect,
                                    /*antialias=*/true),  // <overflow-clip>
          PaintOpIs<cc::DrawScrollingContentsOp>(),       // chunk 1
          PaintOpIs<cc::RestoreOp>(),                     // </overflow-clip>
          PaintOpIs<cc::DrawRecordOp>(),                  // chunk 2
          PaintOpIs<cc::RestoreOp>(),                     // </effect>
          // The rest of the scrolling contents not under the effect
          // needs another DrawScrollingContentsOp.
          PaintOpIs<cc::SaveOp>(),
          PaintOpEq<cc::ClipRectOp>(SkRect::MakeXYWH(5, 5, 20, 30),
                                    SkClipOp::kIntersect,
                                    /*antialias=*/true),  // <overflow-clip>
          PaintOpIs<cc::DrawScrollingContentsOp>(),       // chunk 3
          PaintOpIs<cc::RestoreOp>(),                     // </overflow-clip>
          PaintOpIs<cc::DrawRecordOp>()));                // chunk 4

  EXPECT_EQ(
      gfx::Rect(5, 5, 20, 30),
      cc_list->raster_inducing_scrolls()
          .at(scroll_state.Transform().ScrollNode()->GetCompositorElementId())
          .visual_rect);
  const auto& scrolling_contents_op1 =
      static_cast<const cc::DrawScrollingContentsOp&>(
          cc_list->paint_op_buffer().GetOpAtForTesting(4));
  ASSERT_EQ(cc::PaintOpType::kDrawScrollingContents,
            scrolling_contents_op1.GetType());
  EXPECT_THAT(
      scrolling_contents_op1.display_item_list->paint_op_buffer(),
      ElementsAre(PaintOpIs<cc::SaveOp>(),
                  PaintOpEq<cc::ConcatOp>(
                      SkM44::Scale(2, 2)),  // <transform_under_scroll>
                  PaintOpEq<cc::ClipRectOp>(
                      SkRect::MakeXYWH(0, 0, 1, 1), SkClipOp::kIntersect,
                      /*antialias=*/true),        // <clip_under_scroll>
                  PaintOpIs<cc::DrawRecordOp>(),  // chunk 1
                  PaintOpIs<cc::RestoreOp>()));   // </clip_under_scroll>
                                                  // </transform_under_scroll>

  const auto& scrolling_contents_op2 =
      static_cast<const cc::DrawScrollingContentsOp&>(
          cc_list->paint_op_buffer().GetOpAtForTesting(10));
  ASSERT_EQ(cc::PaintOpType::kDrawScrollingContents,
            scrolling_contents_op2.GetType());
  EXPECT_THAT(
      scrolling_contents_op2.display_item_list->paint_op_buffer(),
      ElementsAre(PaintOpIs<cc::SaveOp>(),
                  PaintOpEq<cc::ConcatOp>(
                      SkM44::Scale(2, 2)),  // <transform_under_scroll>
                  PaintOpEq<cc::ClipRectOp>(
                      SkRect::MakeXYWH(0, 0, 1, 1), SkClipOp::kIntersect,
                      /*antialias=*/true),        // <clip_under_scroll>
                  PaintOpIs<cc::DrawRecordOp>(),  // chunk 3
                  PaintOpIs<cc::RestoreOp>()));   // </clip_under_scroll>
                                                  // </transform_under_scroll>
}

TEST_P(PaintChunksToCcLayerTest, NestedScrollingContentsIntoDisplayItemList) {
  if (!RuntimeEnabledFeatures::RasterInducingScrollEnabled()) {
    GTEST_SKIP();
  }

  auto scroll_state1 = CreateScrollTranslationState(
      PropertyTreeState::Root(), -50, -60, gfx::Rect(5, 5, 20, 30),
      gfx::Size(100, 200));
  auto scroll_state2 = CreateScrollTranslationState(
      scroll_state1, -70, -80, gfx::Rect(10, 20, 30, 40), gfx::Size(200, 300));

  TestChunks chunks;
  chunks.AddChunk(t0(), c0(), e0());
  chunks.AddChunk(scroll_state1);
  chunks.AddChunk(scroll_state2);
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
                        /*antialias=*/true),  // <overflow-clip1>
                    PaintOpIs<cc::DrawScrollingContentsOp>(),
                    PaintOpIs<cc::RestoreOp>(),       // </overflow-clip1>
                    PaintOpIs<cc::DrawRecordOp>()));  // chunk 3
    EXPECT_EQ(gfx::Rect(5, 5, 20, 30), cc_list->raster_inducing_scrolls()
                                           .at(scroll_state1.Transform()
                                                   .ScrollNode()
                                                   ->GetCompositorElementId())
                                           .visual_rect);
    EXPECT_EQ(gfx::Rect(5, 5, 20, 30), cc_list->raster_inducing_scrolls()
                                           .at(scroll_state2.Transform()
                                                   .ScrollNode()
                                                   ->GetCompositorElementId())
                                           .visual_rect);
    const auto& scrolling_contents_op1 =
        static_cast<const cc::DrawScrollingContentsOp&>(
            cc_list->paint_op_buffer().GetOpAtForTesting(3));
    ASSERT_EQ(cc::PaintOpType::kDrawScrollingContents,
              scrolling_contents_op1.GetType());
    EXPECT_THAT(
        scrolling_contents_op1.display_item_list->paint_op_buffer(),
        ElementsAre(PaintOpIs<cc::DrawRecordOp>(),  // chunk 1
                    PaintOpIs<cc::SaveOp>(),
                    PaintOpEq<cc::ClipRectOp>(
                        SkRect::MakeXYWH(10, 20, 30, 40), SkClipOp::kIntersect,
                        /*antialias=*/true),  // <overflow-clip2>
                    PaintOpIs<cc::DrawScrollingContentsOp>(),
                    PaintOpIs<cc::RestoreOp>()));  // </overflow-clip2>
    const auto& scrolling_contents_op2 =
        static_cast<const cc::DrawScrollingContentsOp&>(
            scrolling_contents_op1.display_item_list->paint_op_buffer()
                .GetOpAtForTesting(3));
    ASSERT_EQ(cc::PaintOpType::kDrawScrollingContents,
              scrolling_contents_op2.GetType());
    EXPECT_THAT(scrolling_contents_op2.display_item_list->paint_op_buffer(),
                ElementsAre(PaintOpIs<cc::DrawRecordOp>()));  // chunk 2
  } else {
    EXPECT_THAT(
        cc_list->paint_op_buffer(),
        ElementsAre(
            PaintOpIs<cc::DrawRecordOp>(),  // chunk 0
            PaintOpIs<cc::SaveOp>(),
            PaintOpEq<cc::ClipRectOp>(SkRect::MakeXYWH(5, 5, 20, 30),
                                      SkClipOp::kIntersect,
                                      /*antialias=*/true),  // <overflow-clip1>
            PaintOpIs<cc::SaveOp>(),
            PaintOpEq<cc::TranslateOp>(-50, -60),  // <scroll-translation1>
            PaintOpIs<cc::DrawRecordOp>(),         // chunk 1
            PaintOpIs<cc::SaveOp>(),
            PaintOpEq<cc::ClipRectOp>(SkRect::MakeXYWH(10, 20, 30, 40),
                                      SkClipOp::kIntersect,
                                      /*antialias=*/true),  // <overflow-clip1>
            PaintOpIs<cc::SaveOp>(),
            PaintOpEq<cc::TranslateOp>(-70, -80),  // <scroll-translation2>
            PaintOpIs<cc::DrawRecordOp>(),         // chunk 2
            PaintOpIs<cc::RestoreOp>(),            // </scroll-translation2>
            PaintOpIs<cc::RestoreOp>(),            // </overflow-clip2>
            PaintOpIs<cc::RestoreOp>(),            // </scroll-translation1>
            PaintOpIs<cc::RestoreOp>(),            // </overflow-clip1>
            PaintOpIs<cc::DrawRecordOp>()));       // chunk 3
  }
}

TEST_P(PaintChunksToCcLayerTest,
       NestedScrollingContentsIntoDisplayItemListStartingFromNestedState) {
  if (!RuntimeEnabledFeatures::RasterInducingScrollEnabled()) {
    GTEST_SKIP();
  }

  auto scroll_state1 = CreateScrollTranslationState(
      PropertyTreeState::Root(), -50, -60, gfx::Rect(5, 5, 20, 30),
      gfx::Size(100, 200));
  auto scroll_state2 = CreateScrollTranslationState(
      scroll_state1, -70, -80, gfx::Rect(10, 20, 30, 40), gfx::Size(200, 300));
  auto* transform_under_scroll =
      CreateTransform(scroll_state2.Transform(), MakeScaleMatrix(2));
  auto* clip_under_scroll =
      CreateClip(scroll_state2.Clip(), *transform_under_scroll,
                 FloatRoundedRect(0.f, 0.f, 1.f, 1.f));
  auto* effect_under_scroll = CreateOpacityEffect(
      scroll_state2.Effect(), *transform_under_scroll, clip_under_scroll, 0.5f);

  TestChunks chunks;
  chunks.AddChunk(t0(), c0(), e0());
  chunks.AddChunk(*transform_under_scroll, *clip_under_scroll,
                  *effect_under_scroll, gfx::Rect(1, 2, 67, 82));
  chunks.AddChunk(scroll_state1);

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
                  PaintOpIs<cc::RestoreOp>()));  // </overflow-clip>
  EXPECT_EQ(
      gfx::Rect(5, 5, 20, 30),
      cc_list->raster_inducing_scrolls()
          .at(scroll_state1.Transform().ScrollNode()->GetCompositorElementId())
          .visual_rect);
  EXPECT_EQ(
      gfx::Rect(5, 5, 20, 30),
      cc_list->raster_inducing_scrolls()
          .at(scroll_state2.Transform().ScrollNode()->GetCompositorElementId())
          .visual_rect);
  const auto& scrolling_contents_op1 =
      static_cast<const cc::DrawScrollingContentsOp&>(
          cc_list->paint_op_buffer().GetOpAtForTesting(3));
  ASSERT_EQ(cc::PaintOpType::kDrawScrollingContents,
            scrolling_contents_op1.GetType());
  EXPECT_THAT(
      scrolling_contents_op1.display_item_list->paint_op_buffer(),
      ElementsAre(PaintOpIs<cc::SaveOp>(),
                  PaintOpEq<cc::ClipRectOp>(
                      SkRect::MakeXYWH(10, 20, 30, 40), SkClipOp::kIntersect,
                      /*antialias=*/true),  // <overflow-clip2>
                  PaintOpIs<cc::DrawScrollingContentsOp>(),
                  PaintOpIs<cc::RestoreOp>(),       // </overflow-clip2>
                  PaintOpIs<cc::DrawRecordOp>()));  // chunk 2
  const auto& scrolling_contents_op2 =
      static_cast<const cc::DrawScrollingContentsOp&>(
          scrolling_contents_op1.display_item_list->paint_op_buffer()
              .GetOpAtForTesting(2));
  ASSERT_EQ(cc::PaintOpType::kDrawScrollingContents,
            scrolling_contents_op2.GetType());
  EXPECT_THAT(
      scrolling_contents_op2.display_item_list->paint_op_buffer(),
      ElementsAre(PaintOpIs<cc::SaveOp>(),
                  PaintOpEq<cc::ConcatOp>(
                      SkM44::Scale(2, 2)),  // <transform_under_scroll>
                  PaintOpEq<cc::ClipRectOp>(
                      SkRect::MakeXYWH(0, 0, 1, 1), SkClipOp::kIntersect,
                      /*antialias=*/true),            // <clip_under_scroll>
                  PaintOpIs<cc::SaveLayerAlphaOp>(),  // <effect_under_scroll>
                  PaintOpIs<cc::DrawRecordOp>(),      // chunk 1
                  PaintOpIs<cc::RestoreOp>(),         // </effect_under_scroll>
                  PaintOpIs<cc::RestoreOp>()));       // </clip_under_scroll>
                                                 // </transform_under_scroll>
}

// This tests the following situation with prefer-compositing-to-lcd-text
// enabled:
// <iframe style="width: 300px; height: 300px" srcdoc='
//   <style>body { overflow: hidden }</style>
//   ...
//   <div id="bg" style="width: 50px; height: 500px; background-image: ...;
//                       background-attachment: fixed"></div>
//   </div>
//   ...
//   <script>window.scrollTo(0, 10);</script>
// '></iframe>
// The painter creates a kFixedAttachmentBackground display item whose clip
// state is the background clip which is in the scrolling contents space and
// transform is in the border box space of the frame. The fixed-attachment
// background is not composited because the scroll is not composited.
TEST_P(PaintChunksToCcLayerTest, NonCompositedFixedAttachmentBackground) {
  if (!RuntimeEnabledFeatures::RasterInducingScrollEnabled()) {
    GTEST_SKIP();
  }

  auto scroll_state = CreateScrollTranslationState(
      PropertyTreeState::Root(), -50, -60, gfx::Rect(5, 5, 20, 30),
      gfx::Size(100, 200));
  auto* background_clip =
      CreateClip(scroll_state.Clip(), scroll_state.Transform(),
                 FloatRoundedRect(0.f, 0.f, 10.f, 10.f));

  TestChunks chunks;
  chunks.AddChunk(t0(), c0(), e0());
  chunks.AddChunk(scroll_state);
  // The fixed-attachment background.
  chunks.AddChunk(t0(), *background_clip, e0());
  chunks.AddChunk(scroll_state);

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
                  PaintOpIs<cc::SaveOp>(), PaintOpEq<cc::TranslateOp>(-50, -60),
                  PaintOpEq<cc::ClipRectOp>(
                      SkRect::MakeXYWH(0, 0, 10, 10), SkClipOp::kIntersect,
                      /*antialias=*/true),  // <background-clip>
                  PaintOpIs<cc::SaveOp>(), PaintOpEq<cc::TranslateOp>(50, 60),
                  PaintOpIs<cc::DrawRecordOp>(),  // chunk 2: fixed bg
                  PaintOpIs<cc::RestoreOp>(),
                  PaintOpIs<cc::RestoreOp>(),  // </background-clip>
                  PaintOpIs<cc::DrawScrollingContentsOp>(),
                  PaintOpIs<cc::RestoreOp>()));  // </overflow-clip>
  EXPECT_EQ(
      gfx::Rect(5, 5, 20, 30),
      cc_list->raster_inducing_scrolls()
          .at(scroll_state.Transform().ScrollNode()->GetCompositorElementId())
          .visual_rect);
  const auto& scrolling_contents_op1 =
      static_cast<const cc::DrawScrollingContentsOp&>(
          cc_list->paint_op_buffer().GetOpAtForTesting(3));
  ASSERT_EQ(cc::PaintOpType::kDrawScrollingContents,
            scrolling_contents_op1.GetType());
  EXPECT_THAT(scrolling_contents_op1.display_item_list->paint_op_buffer(),
              ElementsAre(PaintOpIs<cc::DrawRecordOp>(),  // chunk 1
                          PaintOpIs<cc::SaveOp>(), PaintOpIs<cc::ClipRectOp>(),
                          PaintOpIs<cc::RestoreOp>()));
  const auto& scrolling_contents_op2 =
      static_cast<const cc::DrawScrollingContentsOp&>(
          cc_list->paint_op_buffer().GetOpAtForTesting(12));
  ASSERT_EQ(cc::PaintOpType::kDrawScrollingContents,
            scrolling_contents_op2.GetType());
  EXPECT_THAT(scrolling_contents_op2.display_item_list->paint_op_buffer(),
              ElementsAre(PaintOpIs<cc::DrawRecordOp>()));  // chunk 3
}

TEST_P(PaintChunksToCcLayerTest,
       UpdateLayerPropertiesRegionCaptureDataSetOnLayer) {
  auto layer = cc::Layer::Create();

  TestChunks chunks;
  chunks.AddChunk(t0(), c0(), e0(), gfx::Rect(5, 10, 200, 300),
                  gfx::Rect(10, 15, 20, 30));

  const auto kCropId = RegionCaptureCropId(base::Token::CreateRandom());
  chunks.GetChunks().back().region_capture_data =
      MakeRegionCaptureData({{kCropId, gfx::Rect(50, 60, 100, 200)}});

  UpdateLayerProperties(*layer, PropertyTreeState::Root(), chunks.Build());

  const gfx::Rect actual_bounds =
      layer->capture_bounds().bounds().find(kCropId.value())->second;
  EXPECT_EQ((gfx::Rect{50, 60, 100, 200}), actual_bounds);
}

TEST_P(PaintChunksToCcLayerTest,
       UpdateLayerPropertiesRegionCaptureDataUsesLayerOffset) {
  auto layer = cc::Layer::Create();
  layer->SetOffsetToTransformParent(gfx::Vector2dF{10, 15});
  TestChunks chunks;
  chunks.AddChunk(t0(), c0(), e0(), gfx::Rect(5, 10, 200, 300),
                  gfx::Rect(10, 15, 20, 30));

  const auto kCropId = RegionCaptureCropId(base::Token::CreateRandom());
  chunks.GetChunks().back().region_capture_data =
      MakeRegionCaptureData({{kCropId, gfx::Rect(50, 60, 100, 200)}});

  UpdateLayerProperties(*layer, PropertyTreeState::Root(), chunks.Build());

  const gfx::Rect actual_bounds =
      layer->capture_bounds().bounds().find(kCropId.value())->second;
  EXPECT_EQ((gfx::Rect{40, 45, 100, 200}), actual_bounds);
}

TEST_P(PaintChunksToCcLayerTest, UpdateLayerPropertiesRegionCaptureDataEmpty) {
  auto layer = cc::Layer::Create();
  TestChunks chunks;
  chunks.AddChunk(t0(), c0(), e0(), gfx::Rect(5, 10, 200, 300),
                  gfx::Rect(10, 15, 20, 30));
  UpdateLayerProperties(*layer, PropertyTreeState::Root(), chunks.Build());
  EXPECT_TRUE(layer->capture_bounds().bounds().empty());
}

TEST_P(PaintChunksToCcLayerTest,
       UpdateLayerPropertiesRegionCaptureDataEmptyBounds) {
  auto layer = cc::Layer::Create();

  TestChunks chunks;
  chunks.AddChunk(t0(), c0(), e0(), gfx::Rect(5, 10, 200, 300),
                  gfx::Rect(10, 15, 20, 30));

  const auto kCropId = RegionCaptureCropId(base::Token::CreateRandom());
  chunks.GetChunks().back().region_capture_data =
      MakeRegionCaptureData({{kCropId, gfx::Rect()}});

  UpdateLayerProperties(*layer, PropertyTreeState::Root(), chunks.Build());

  const gfx::Rect actual_bounds =
      layer->capture_bounds().bounds().find(kCropId.value())->second;
  EXPECT_TRUE(actual_bounds.IsEmpty());
}

TEST_P(PaintChunksToCcLayerTest,
       UpdateLayerPropertiesRegionCaptureDataMultipleChunks) {
  auto layer = cc::Layer::Create();

  TestChunks chunks;

  // Add the first chunk with region capture bounds.
  chunks.AddChunk(t0(), c0(), e0(), gfx::Rect(5, 10, 200, 300),
                  gfx::Rect(10, 15, 20, 30));
  const auto kCropId = RegionCaptureCropId(base::Token::CreateRandom());
  chunks.GetChunks().back().region_capture_data =
      MakeRegionCaptureData({{kCropId, gfx::Rect(50, 60, 100, 200)}});

  // Add a second chunk with additional region capture bounds.
  chunks.AddChunk(t0(), c0(), e0(), gfx::Rect(6, 12, 244, 366),
                  gfx::Rect(20, 30, 40, 60));
  const auto kSecondCropId = RegionCaptureCropId(base::Token::CreateRandom());
  const auto kThirdCropId = RegionCaptureCropId(base::Token::CreateRandom());
  chunks.GetChunks().back().region_capture_data =
      MakeRegionCaptureData({{kSecondCropId, gfx::Rect(51, 61, 101, 201)},
                             {kThirdCropId, gfx::Rect(52, 62, 102, 202)}});

  UpdateLayerProperties(*layer, PropertyTreeState::Root(), chunks.Build());

  EXPECT_EQ((gfx::Rect{50, 60, 100, 200}),
            layer->capture_bounds().bounds().find(kCropId.value())->second);
  EXPECT_EQ(
      (gfx::Rect{51, 61, 101, 201}),
      layer->capture_bounds().bounds().find(kSecondCropId.value())->second);
  EXPECT_EQ(
      (gfx::Rect{52, 62, 102, 202}),
      layer->capture_bounds().bounds().find(kThirdCropId.value())->second);
}

TEST_P(PaintChunksToCcLayerTest, NonCompositedBackdropFilter) {
  CompositorFilterOperations filter;
  filter.AppendBlurFilter(5);
  auto* e1 = CreateBackdropFilterEffect(e0(), filter);
  TestChunks chunks;
  chunks.AddChunk(t0(), c0(), *e1, gfx::Rect(0, 0, 50, 50));

  PaintRecord output =
      PaintChunksToCcLayer::Convert(chunks.Build(), PropertyTreeState::Root());
  // TODO(crbug.com/1334293): For now non-composited backdrop filters are
  // ignored.
  EXPECT_THAT(output, ElementsAre(PaintOpIs<cc::SaveLayerAlphaOp>(),
                                  PaintOpIs<cc::DrawRecordOp>(),
                                  PaintOpIs<cc::RestoreOp>()));
}

}  // namespace
}  // namespace blink
```