Response:
The user wants a summary of the functionality of the provided C++ code snippet. This code is part of a test file (`geometry_mapper_test.cc`) within the Chromium Blink rendering engine. Therefore, the functionality relates to testing the `GeometryMapper` class.

The code defines several test cases using the `TEST_P` macro, suggesting these are parameterized tests. Each test case sets up different scenarios involving transforms, clips, and filters, and then uses the `GeometryMapper` to perform geometric calculations (like mapping rectangles between coordinate spaces). The tests then assert that the results are as expected.

Here's a breakdown of the functionality demonstrated in the provided code:

1. **Testing transformations:**  Various tests involve applying transformations (translation, rotation, scale) and verifying how the `GeometryMapper` maps rectangles between different transformed spaces.

2. **Testing clipping:** Several tests incorporate clipping rectangles and verify how `GeometryMapper` handles these constraints when mapping geometries. This includes cases with multiple nested clips and the order of application.

3. **Testing filters:** Some tests introduce filters (blur, reflection) and examine how `GeometryMapper` accounts for the visual effects of these filters when determining geometry. This includes cases with animating filters and filter aliases.

4. **Testing the interaction of transforms, clips, and filters:** Many tests combine these different properties to create complex scenarios and ensure `GeometryMapper` can correctly handle their combined effect.

5. **Testing edge cases and specific scenarios:**  Tests cover situations like:
    *   Transform animations and their impact on visual rects.
    *   Sticky positioning and its interaction with clips.
    *   Sibling transforms requiring traversal through the root.
    *   Precision issues with chained transformations.
    *   The `MightOverlapForCompositing` function, particularly in scenarios involving fixed-position elements and scrolling.

6. **Testing specific functionalities of `GeometryMapper`:**  The tests call specific methods of the `GeometryMapper` class like `LocalToAncestorVisualRect`, `SourceToDestinationRect`, and `SourceToDestinationProjection`.

To answer the user's specific requests:

*   **Functionality:**  The code tests the geometric mapping capabilities of the `GeometryMapper` class in Blink. It verifies how the class handles transformations, clips, and filters when mapping rectangles between different coordinate spaces.

*   **Relationship with JavaScript, HTML, CSS:**
    *   **Transforms (CSS):**  The transformations tested (translation, rotation, scale) directly correspond to CSS `transform` properties. The tests ensure that Blink correctly calculates the visual representation of elements with these transforms. *Example:* A CSS rule `transform: rotate(45deg);` applied to an HTML element will cause a rotation. These tests verify Blink's ability to calculate the bounding box of this rotated element.
    *   **Clipping (CSS):** The clips in the tests relate to CSS `clip-path` or the implicit clipping caused by overflow properties. The tests ensure that Blink correctly restricts the visible area of elements based on these clips. *Example:* A CSS rule `clip-path: polygon(0 0, 100px 0, 100px 100px, 0 100px);` will clip an element to a square. These tests verify that Blink correctly calculates the visible portion of the element.
    *   **Filters (CSS):** The filters tested (blur, reflection) correspond to CSS `filter` properties. The tests ensure Blink accurately calculates the visual bounds of elements with applied filters. *Example:* A CSS rule `filter: blur(5px);` will apply a blur effect. These tests verify that Blink correctly determines the bounding box of the blurred element, which might be larger than the original element.
    *   **Fixed Positioning (CSS):** The `MightOverlapForCompositing` tests involving fixed positioning relate to the CSS `position: fixed;` property. These tests ensure Blink correctly determines if elements with fixed positioning overlap with other elements, considering scrolling.

*   **Logic Inference (Hypothetical Input/Output):**  Consider the `SiblingTransforms` test.
    *   **Input:** A rectangle at (0, 0, 100, 100) with a 45-degree rotation transform, and a target space with a -45-degree rotation transform.
    *   **Output:** The mapped rectangle in the target space will be approximately (-100, 0, 100, 100). The rotation in opposite directions effectively creates a horizontal shift in this specific scenario.

*   **User/Programming Errors:**
    *   **Incorrectly assuming transform order:**  If a developer applies multiple transforms in CSS, the order matters. These tests implicitly verify that Blink applies transforms correctly in their defined order. A user might incorrectly assume a different order of application, leading to unexpected visual results.
    *   **Not considering filter expansion:** Filters like blur can expand the visual bounds of an element. A developer might calculate layout based on the original bounds and not account for the filter's expansion, leading to content being clipped or overlapping unexpectedly. The tests with filters ensure Blink correctly handles this expansion.
    *   **Misunderstanding fixed positioning:** Developers might incorrectly assume a fixed element's position is relative to its parent without considering the viewport. The `MightOverlapFixed` tests verify Blink's correct handling of fixed positioning and scrolling interactions.

Based on the provided snippet being the *second part* of the file, the overall function can be summarized as: **This section of the `geometry_mapper_test.cc` file continues testing the `GeometryMapper` class with more complex scenarios involving combinations of transforms, clips, filters, and specific layout situations like fixed positioning and scrolling.** It focuses on verifying the correctness of geometric calculations in these advanced cases.
这是 `blink/renderer/platform/graphics/paint/geometry_mapper_test.cc` 文件的第二部分，延续了第一部分的功能，主要集中在测试 Blink 引擎中 `GeometryMapper` 类的各种几何映射功能。`GeometryMapper` 负责在不同的坐标空间之间转换几何信息，例如矩形和裁剪区域。

**归纳一下这部分的功能：**

这部分主要测试了 `GeometryMapper` 在更复杂的场景下的表现，涵盖了以下方面：

1. **变换动画和粘滞定位的影响:** 测试了变换动画和粘滞定位（sticky positioning）如何影响视觉矩形的计算，尤其是在有多个裁剪的情况下的行为。

2. **兄弟变换的映射:** 验证了在具有兄弟关系的变换节点之间进行坐标映射时，`GeometryMapper` 是否能正确处理，需要通过根节点进行转换。

3. **带有裁剪的兄弟变换:**  测试了在兄弟变换场景下引入裁剪节点时，`GeometryMapper` 如何进行坐标映射，特别是当源和目标的裁剪节点没有祖先关系时的情况。

4. **带有滤镜、裁剪和变换的复杂场景:** 深入测试了当同时存在变换、裁剪和滤镜效果时，`GeometryMapper` 如何计算视觉矩形。这包括了普通滤镜和使用别名的滤镜。

5. **动画滤镜的影响:**  测试了动画滤镜如何导致视觉矩形扩展到无限大，并被后续的裁剪节点裁剪。

6. **反射滤镜的处理:** 验证了 `GeometryMapper` 如何处理反射滤镜产生的视觉效果，并计算相应的视觉矩形。

7. **忽略滤镜选项:** 引入了忽略滤镜的选项，测试在不考虑滤镜影响的情况下进行几何映射。

8. **精度测试:**  测试在高精度变换场景下，`GeometryMapper` 是否能保持计算的准确性。

9. **潜在重叠的判断 (`MightOverlap`):**  大量测试集中在 `MightOverlapForCompositing` 函数上，该函数用于判断两个元素在合成时是否可能发生重叠。这包括：
    *   简单的变换场景。
    *   具有共同裁剪祖先的场景。
    *   固定定位元素的重叠判断，考虑了视口和滚动的影响。
    *   带有缩放变换的固定定位元素。
    *   带有滚动裁剪的固定定位元素。
    *   涉及多层嵌套滚动容器的重叠判断，涵盖了在滚动容器内外元素之间的重叠判断逻辑。

**与 Javascript, HTML, CSS 功能的关系：**

*   **CSS Transforms:** 代码中大量使用了 `MakeRotationMatrix`, `MakeTranslationMatrix`, `MakeScaleMatrix` 等函数创建变换矩阵，这些都直接对应于 CSS 的 `transform` 属性，如 `rotate()`, `translate()`, `scale()` 等。测试验证了当 HTML 元素应用这些 CSS 变换时，Blink 引擎是否能正确计算其在屏幕上的位置和形状。
    *   **举例:**  一个 HTML 元素设置了 `style="transform: rotate(45deg);"`，这个测试会验证 `GeometryMapper` 能否正确计算旋转后的元素的边界。

*   **CSS Clipping:** `CreateClip` 函数创建了裁剪区域，对应于 CSS 的 `clip-path` 属性或 `overflow: hidden` 等属性造成的裁剪。测试确保 Blink 能正确计算被裁剪后的元素的可见区域。
    *   **举例:**  一个 HTML 元素设置了 `style="clip-path: polygon(0 0, 100px 0, 100px 100px, 0 100px);"`，测试会验证 `GeometryMapper` 能否正确计算该多边形裁剪区域内的元素部分。

*   **CSS Filters:** `CreateFilterEffect` 创建了滤镜效果，对应于 CSS 的 `filter` 属性，如 `blur()`, `reflect()` 等。测试确保 Blink 能正确计算应用滤镜后的元素的视觉边界，因为有些滤镜会改变元素的大小。
    *   **举例:**  一个 HTML 元素设置了 `style="filter: blur(5px);"`，测试会验证 `GeometryMapper` 能否考虑到模糊效果带来的边界扩展。

*   **CSS Position (Fixed 和 Sticky):** `CreateFixedPositionTranslation` 和 `CompositingReason::kStickyPosition` 涉及到 CSS 的 `position: fixed;` 和 `position: sticky;` 属性。`MightOverlap` 的相关测试验证了 Blink 如何判断固定定位或粘滞定位元素与其他元素是否重叠，尤其是在滚动发生时。
    *   **举例:**  一个 HTML 元素设置了 `style="position: fixed; top: 10px; left: 20px;"`，`MightOverlap` 测试会验证 Blink 是否能正确判断该元素与其他滚动内容或固定定位元素之间的重叠关系。

**逻辑推理的假设输入与输出：**

以 `TEST_P(GeometryMapperTest, SiblingTransforms)` 为例：

*   **假设输入:**
    *   一个矩形 `input_rect = gfx::RectF(0, 0, 100, 100)`。
    *   一个旋转 45 度的变换 `rotate_transform1`。
    *   一个旋转 -45 度的变换 `rotate_transform2`。
    *   目标是将 `input_rect` 从 `rotate_transform1` 的坐标空间映射到 `rotate_transform2` 的坐标空间。

*   **输出:**
    *   期望的映射后的裁剪矩形 `expected_clip = FloatClipRect(gfx::RectF(-100, 0, 100, 100))`。由于旋转，即使最终叠加效果是平移，出于保守考虑，`IsTight()` 被设置为 `false`。
    *   期望的映射后的普通矩形 `EXPECT_RECTF_NEAR(gfx::RectF(-100, 0, 100, 100), result, 1e-12f)`。

**涉及用户或者编程常见的使用错误：**

*   **不理解变换的顺序:**  CSS 中的变换是按照书写顺序应用的。开发者可能会错误地假设变换的执行顺序，导致最终的视觉效果与预期不符。`GeometryMapper` 的测试确保了 Blink 按照正确的顺序应用变换。
    *   **举例:**  `transform: rotate(45deg) translate(10px, 20px);` 和 `transform: translate(10px, 20px) rotate(45deg);` 的结果是不同的。

*   **忽略滤镜对元素尺寸的影响:** 某些滤镜（如 `blur`）会扩展元素的视觉边界。开发者在计算布局或进行碰撞检测时，如果没有考虑到滤镜的这种影响，可能会导致错误。
    *   **举例:**  一个元素应用了模糊滤镜后，其 `getBoundingClientRect()` 返回的尺寸会比未应用滤镜时大，如果开发者仍然使用未应用滤镜时的尺寸进行后续计算，可能会出现问题。

*   **错误地理解固定定位元素的行为:**  开发者可能会错误地认为固定定位元素是相对于其父元素定位的，而实际上它是相对于视口定位的。这会导致在滚动页面时，固定定位元素的位置与预期不符。`MightOverlapFixed` 的测试就旨在验证 Blink 对固定定位元素行为的正确处理。

总而言之，这部分 `geometry_mapper_test.cc` 文件通过大量的测试用例，覆盖了 `GeometryMapper` 在各种复杂场景下的几何映射功能，确保 Blink 引擎能够准确地计算和处理元素的几何信息，从而正确渲染网页。这些测试直接关联到 CSS 的变换、裁剪、滤镜以及定位等属性，并能帮助开发者避免一些常见的 CSS 使用错误。

### 提示词
```
这是目录为blink/renderer/platform/graphics/paint/geometry_mapper_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
_transform_animation = true;
  expected_visual_rect = FloatClipRect(input_rect);
  expected_visual_rect.Map(*expected_transform);
  expected_visual_rect.Intersect(expected_clip);
  EXPECT_FALSE(expected_visual_rect.IsTight());
  // The visual rect is expanded to infinity because of the transform animation,
  // then clipped by clip1. clip2 doesn't apply because it's below the animating
  // transform.
  expected_visual_rect_expanded_for_compositing = clip1->LayoutClipRect();
  expected_visual_rect_expanded_for_compositing->ClearIsTight();
  CheckMappings();
}

TEST_P(GeometryMapperTest, ExpandVisualRectWithTwoClipsWithStickyBetween) {
  auto* clip1 = CreateClip(c0(), t0(), FloatRoundedRect(10, 10, 200, 200));
  expected_transform = MakeTranslationMatrix(0, 100);
  local_transform = CreateTransform(t0(), *expected_transform, gfx::Point3F(),
                                    CompositingReason::kStickyPosition);
  auto* clip2 =
      CreateClip(*clip1, *local_transform, FloatRoundedRect(10, 10, 200, 200));
  local_clip = clip2;

  input_rect = gfx::RectF(0, 0, 100, 100);
  expected_transformed_rect = expected_transform->MapRect(input_rect);

  expected_clip = clip2->LayoutClipRect();
  expected_clip.Map(*expected_transform);
  expected_clip.Intersect(clip1->LayoutClipRect());
  EXPECT_TRUE(expected_clip.IsTight());
  expected_clip_has_sticky_transform = true;
  expected_visual_rect = FloatClipRect(input_rect);
  expected_visual_rect.Map(*expected_transform);
  expected_visual_rect.Intersect(expected_clip);
  EXPECT_TRUE(expected_visual_rect.IsTight());
  // The visual rect is expanded to infinity because of the sticky transform,
  // then clipped by clip1. clip2 doesn't apply because it's below the sticky
  // transform.
  expected_visual_rect_expanded_for_compositing = clip1->LayoutClipRect();
  expected_visual_rect_expanded_for_compositing->ClearIsTight();
  CheckMappings();
}

TEST_P(GeometryMapperTest, SiblingTransforms) {
  // These transforms are siblings. Thus mapping from one to the other requires
  // going through the root.
  auto rotate_transform1 = MakeRotationMatrix(45);
  auto* transform1 = CreateTransform(t0(), rotate_transform1);

  auto rotate_transform2 = MakeRotationMatrix(-45);
  auto* transform2 = CreateTransform(t0(), rotate_transform2);

  auto transform1_state = PropertyTreeState::Root();
  transform1_state.SetTransform(*transform1);
  auto transform2_state = PropertyTreeState::Root();
  transform2_state.SetTransform(*transform2);

  input_rect = gfx::RectF(0, 0, 100, 100);
  FloatClipRect result_clip(input_rect);
  GeometryMapper::LocalToAncestorVisualRect(transform1_state, transform2_state,
                                            result_clip);
  FloatClipRect expected_clip(gfx::RectF(-100, 0, 100, 100));
  // We convervatively treat any rotated clip rect as not tight, even if it's
  // rotated by 90 degrees.
  expected_clip.ClearIsTight();
  EXPECT_CLIP_RECT_NEAR(expected_clip, result_clip, 1e-12f);

  gfx::RectF result = input_rect;
  GeometryMapper::SourceToDestinationRect(*transform1, *transform2, result);
  EXPECT_RECTF_NEAR(gfx::RectF(-100, 0, 100, 100), result, 1e-12f);

  result_clip = FloatClipRect(input_rect);
  GeometryMapper::LocalToAncestorVisualRect(transform2_state, transform1_state,
                                            result_clip);
  expected_clip = FloatClipRect(gfx::RectF(0, -100, 100, 100));
  expected_clip.ClearIsTight();
  EXPECT_CLIP_RECT_NEAR(expected_clip, result_clip, 1e-12f);

  result = input_rect;
  GeometryMapper::SourceToDestinationRect(*transform2, *transform1, result);
  EXPECT_RECTF_NEAR(gfx::RectF(0, -100, 100, 100), result, 1e-12f);
}

TEST_P(GeometryMapperTest, SiblingTransformsWithClip) {
  // These transforms are siblings. Thus mapping from one to the other requires
  // going through the root.
  auto rotate_transform1 = MakeRotationMatrix(45);
  auto* transform1 = CreateTransform(t0(), rotate_transform1);

  auto rotate_transform2 = MakeRotationMatrix(-45);
  auto* transform2 = CreateTransform(t0(), rotate_transform2);

  auto* clip = CreateClip(c0(), *transform2, FloatRoundedRect(10, 20, 30, 40));

  auto transform1_state = PropertyTreeState::Root();
  transform1_state.SetTransform(*transform1);
  auto transform2_and_clip_state = PropertyTreeState::Root();
  transform2_and_clip_state.SetTransform(*transform2);
  transform2_and_clip_state.SetClip(*clip);

  input_rect = gfx::RectF(0, 0, 100, 100);
  FloatClipRect result(input_rect);
  LocalToAncestorVisualRectInternal(transform1_state, transform2_and_clip_state,
                                    result);
  // Because the clip of the destination state is not an ancestor of the clip
  // of the source state, no clips are applied.
  FloatClipRect expected(gfx::RectF(-100, 0, 100, 100));
  expected.ClearIsTight();
  EXPECT_CLIP_RECT_NEAR(expected, result, 1e-12f);

  result = FloatClipRect(input_rect);
  GeometryMapper::LocalToAncestorVisualRect(transform2_and_clip_state,
                                            transform1_state, result);
  expected = FloatClipRect(gfx::RectF(20, -40, 40, 30));
  // This is because the combined Rotate(45) and Rotate(-45) is not exactly a
  // translation-only transform due to calculation errors.
  expected.ClearIsTight();
  EXPECT_CLIP_RECT_NEAR(expected, result, 1e-12f);
}

TEST_P(GeometryMapperTest, FilterWithClipsAndTransforms) {
  auto* transform_above_effect = Create2DTranslation(t0(), 40, 50);
  auto* transform_below_effect =
      Create2DTranslation(*transform_above_effect, 20, 30);

  // This clip is between transformAboveEffect and the effect.
  auto* clip_above_effect = CreateClip(c0(), *transform_above_effect,
                                       FloatRoundedRect(-100, -100, 200, 200));

  CompositorFilterOperations filters;
  filters.AppendBlurFilter(20);
  auto* effect = CreateFilterEffect(e0(), *transform_above_effect,
                                    clip_above_effect, filters);
  auto* clip_expander =
      CreatePixelMovingFilterClipExpander(*clip_above_effect, *effect);

  // This clip is between the effect and transform_below_effect.
  auto* clip_below_effect = CreateClip(*clip_expander, *transform_above_effect,
                                       FloatRoundedRect(10, 10, 100, 100));

  local_transform = transform_below_effect;
  local_clip = clip_below_effect;
  local_effect = effect;

  input_rect = gfx::RectF(0, 0, 100, 100);
  // 1. transform_below_effect
  auto output = input_rect;
  output.Offset(transform_below_effect->Get2dTranslation());
  // 2. clip_below_effect
  output.Intersect(clip_below_effect->LayoutClipRect().Rect());
  EXPECT_EQ(gfx::RectF(20, 30, 90, 80), output);
  // 3. effect (the outset is 3 times of blur amount).
  output = filters.MapRect(output);
  EXPECT_EQ(gfx::RectF(-40, -30, 210, 200), output);
  // 4. clip_above_effect
  output.Intersect(clip_above_effect->LayoutClipRect().Rect());
  EXPECT_EQ(gfx::RectF(-40, -30, 140, 130), output);
  // 5. transform_above_effect
  output.Offset(transform_above_effect->Get2dTranslation());
  EXPECT_EQ(gfx::RectF(0, 20, 140, 130), output);

  expected_translation_2d = transform_above_effect->Get2dTranslation() +
                            transform_below_effect->Get2dTranslation();
  expected_transformed_rect = input_rect;
  expected_transformed_rect.Offset(expected_translation_2d);
  expected_visual_rect = FloatClipRect(output);
  expected_visual_rect.ClearIsTight();
  expected_clip = FloatClipRect(gfx::RectF(50, 60, 90, 90));
  expected_clip.ClearIsTight();
  CheckMappings();
}

TEST_P(GeometryMapperTest, FilterWithClipsAndTransformsWithAlias) {
  auto* transform_above_effect = Create2DTranslation(t0(), 40, 50);
  auto* transform_below_effect =
      Create2DTranslation(*transform_above_effect, 20, 30);
  local_transform = transform_below_effect;

  // This clip is between transformAboveEffect and the effect.
  auto* clip_above_effect = CreateClip(c0(), *transform_above_effect,
                                       FloatRoundedRect(-100, -100, 200, 200));

  CompositorFilterOperations filters;
  filters.AppendBlurFilter(20);
  auto* real_effect = CreateFilterEffect(e0(), *transform_above_effect,
                                         clip_above_effect, filters);
  auto* clip_expander =
      CreatePixelMovingFilterClipExpander(*clip_above_effect, *real_effect);
  local_effect = EffectPaintPropertyNodeAlias::Create(*real_effect);

  // This clip is between the effect and transformBelowEffect.
  auto* clip_below_effect = CreateClip(*clip_expander, *transform_above_effect,
                                       FloatRoundedRect(10, 10, 100, 100));
  local_clip = clip_below_effect;

  input_rect = gfx::RectF(0, 0, 100, 100);
  // 1. transformBelowEffect
  auto output = input_rect;
  output.Offset(transform_below_effect->Get2dTranslation());
  // 2. clipBelowEffect
  output.Intersect(clip_below_effect->LayoutClipRect().Rect());
  EXPECT_EQ(gfx::RectF(20, 30, 90, 80), output);
  // 3. effect (the outset is 3 times of blur amount).
  output = filters.MapRect(output);
  EXPECT_EQ(gfx::RectF(-40, -30, 210, 200), output);
  // 4. clipAboveEffect
  output.Intersect(clip_above_effect->LayoutClipRect().Rect());
  EXPECT_EQ(gfx::RectF(-40, -30, 140, 130), output);
  // 5. transformAboveEffect
  output.Offset(transform_above_effect->Get2dTranslation());
  EXPECT_EQ(gfx::RectF(0, 20, 140, 130), output);

  expected_translation_2d = transform_above_effect->Get2dTranslation() +
                            transform_below_effect->Get2dTranslation();
  expected_transformed_rect = input_rect;
  expected_transformed_rect.Offset(expected_translation_2d);
  expected_visual_rect = FloatClipRect(output);
  expected_visual_rect.ClearIsTight();
  expected_clip = FloatClipRect(gfx::RectF(50, 60, 90, 90));
  expected_clip.ClearIsTight();
  CheckMappings();
}

TEST_P(GeometryMapperTest,
       ExpandVisualRectWithTwoClipsWithAnimatingFilterBetween) {
  auto* clip1 = CreateClip(c0(), t0(), FloatRoundedRect(10, 10, 200, 200));
  auto* effect =
      CreateAnimatingFilterEffect(e0(), CompositorFilterOperations(), clip1);
  auto* clip_expander = CreatePixelMovingFilterClipExpander(*clip1, *effect);

  auto* clip2 =
      CreateClip(*clip_expander, t0(), FloatRoundedRect(50, 0, 200, 50));
  local_clip = clip2;
  local_effect = effect;

  input_rect = gfx::RectF(0, 0, 100, 100);
  expected_transformed_rect = input_rect;
  auto output = input_rect;
  output.Intersect(clip2->LayoutClipRect().Rect());
  output.Intersect(clip1->LayoutClipRect().Rect());
  EXPECT_EQ(gfx::RectF(50, 10, 50, 40), output);
  expected_visual_rect = FloatClipRect(output);
  expected_visual_rect.ClearIsTight();
  expected_clip = clip2->LayoutClipRect();
  expected_clip.Intersect(clip1->LayoutClipRect());
  expected_clip.ClearIsTight();
  // The visual rect is expanded to infinity because of the filter animation,
  // the clipped by clip1. clip2 doesn't apply because it's below the animating
  // filter.
  expected_visual_rect_expanded_for_compositing = clip1->LayoutClipRect();
  expected_visual_rect_expanded_for_compositing->ClearIsTight();
  CheckMappings();
}

TEST_P(GeometryMapperTest, Reflection) {
  CompositorFilterOperations filters;
  filters.AppendReferenceFilter(paint_filter_builder::BuildBoxReflectFilter(
      BoxReflection(BoxReflection::kHorizontalReflection, 0), nullptr));
  auto* effect = CreateFilterEffect(e0(), filters);
  auto* clip_expander = CreatePixelMovingFilterClipExpander(c0(), *effect);

  local_effect = effect;
  local_clip = clip_expander;

  input_rect = gfx::RectF(100, 100, 50, 50);
  expected_transformed_rect = input_rect;
  // Reflection is at (50, 100, 50, 50).
  expected_visual_rect = FloatClipRect(gfx::RectF(-150, 100, 300, 50));
  expected_visual_rect.ClearIsTight();
  expected_clip.ClearIsTight();

  CheckMappings();
}

TEST_P(GeometryMapperTest, IgnoreFilters) {
  CompositorFilterOperations filters;
  filters.AppendReferenceFilter(paint_filter_builder::BuildBoxReflectFilter(
      BoxReflection(BoxReflection::kHorizontalReflection, 0), nullptr));
  auto* effect = CreateFilterEffect(e0(), filters);
  auto* clip_expander = CreatePixelMovingFilterClipExpander(c0(), *effect);

  local_effect = effect;
  local_clip = clip_expander;

  // Test with filters to ensure test is correctly set up.
  FloatClipRect actual_clip_rect(gfx::RectF(100, 100, 50, 50));
  GeometryMapper::LocalToAncestorVisualRect(LocalState(), AncestorState(),
                                            actual_clip_rect);
  FloatClipRect expected_with_filter(gfx::RectF(-150, 100, 300, 50));
  expected_with_filter.ClearIsTight();
  EXPECT_CLIP_RECT_EQ(expected_with_filter, actual_clip_rect);

  // Test with filters ignored.
  actual_clip_rect.SetRect(gfx::RectF(100, 100, 50, 50));
  GeometryMapper::LocalToAncestorVisualRect(
      LocalState(), AncestorState(), actual_clip_rect,
      kIgnoreOverlayScrollbarSize, kIgnoreFilters);
  FloatClipRect expected_without_filter(gfx::RectF(100, 100, 50, 50));
  // We still conservatively clear the tight flag.
  expected_without_filter.ClearIsTight();
  EXPECT_CLIP_RECT_EQ(expected_without_filter, actual_clip_rect);
}

TEST_P(GeometryMapperTest, Precision) {
  auto* t1 = CreateTransform(t0(), MakeScaleMatrix(32767));
  auto* t2 = CreateTransform(*t1, MakeRotationMatrix(1));
  auto* t3 = Create2DTranslation(*t2, 0, 0);
  auto* t4 = Create2DTranslation(*t3, 0, 0);
  EXPECT_TRUE(
      GeometryMapper::SourceToDestinationProjection(*t4, *t4).IsIdentity());
  EXPECT_TRUE(
      GeometryMapper::SourceToDestinationProjection(*t3, *t4).IsIdentity());
  EXPECT_TRUE(
      GeometryMapper::SourceToDestinationProjection(*t2, *t4).IsIdentity());
  EXPECT_TRUE(
      GeometryMapper::SourceToDestinationProjection(*t3, *t2).IsIdentity());
  EXPECT_TRUE(
      GeometryMapper::SourceToDestinationProjection(*t4, *t2).IsIdentity());
  EXPECT_TRUE(
      GeometryMapper::SourceToDestinationProjection(*t4, *t3).IsIdentity());
  EXPECT_TRUE(
      GeometryMapper::SourceToDestinationProjection(*t2, *t3).IsIdentity());
}

TEST_P(GeometryMapperTest, MightOverlap) {
  auto* t2 = Create2DTranslation(t0(), 99, 0);
  auto* t3 = Create2DTranslation(t0(), 100, 0);
  auto* t4 = CreateAnimatingTransform(t0(), MakeTranslationMatrix(100, 0));

  gfx::RectF r(0, 0, 100, 100);
  PropertyTreeState s1 = PropertyTreeState::Root();
  PropertyTreeState s2(*t2, c0(), e0());
  PropertyTreeState s3(*t3, c0(), e0());
  PropertyTreeState s4(*t4, c0(), e0());

  EXPECT_TRUE(MightOverlapForCompositing(r, s1, r, s1));
  EXPECT_TRUE(MightOverlapForCompositing(r, s1, r, s2));
  EXPECT_FALSE(MightOverlapForCompositing(r, s1, r, s3));
  EXPECT_TRUE(MightOverlapForCompositing(r, s1, r, s4));
}

TEST_P(GeometryMapperTest, MightOverlapCommonClipAncestor) {
  auto* common_clip = CreateClip(c0(), t0(), FloatRoundedRect(0, 100, 101, 99));
  auto* c1 = CreateClip(*common_clip, t0(), FloatRoundedRect(0, 100, 100, 100));
  auto* c2 =
      CreateClip(*common_clip, t0(), FloatRoundedRect(50, 150, 100, 100));
  auto* c3 =
      CreateClip(*common_clip, t0(), FloatRoundedRect(100, 100, 100, 100));
  auto* c4 = CreateClip(*common_clip, t0(), FloatRoundedRect(0, 200, 100, 100));

  gfx::RectF r(0, 100, 200, 100);
  PropertyTreeState s1(t0(), *c1, e0());
  PropertyTreeState s2(t0(), *c2, e0());
  PropertyTreeState s3(t0(), *c3, e0());
  PropertyTreeState s4(t0(), *c4, e0());

  EXPECT_TRUE(MightOverlapForCompositing(r, s1, r, s2));
  EXPECT_FALSE(MightOverlapForCompositing(r, s1, r, s3));
  EXPECT_TRUE(MightOverlapForCompositing(r, s2, r, s3));
  // r in s4 is invisible in common_clip.
  EXPECT_FALSE(MightOverlapForCompositing(r, s2, r, s4));
}

TEST_P(GeometryMapperTest, MightOverlapFixed) {
  auto* viewport = CreateTransform(t0(), gfx::Transform());
  auto scroll_state1 = CreateScrollTranslationState(
      PropertyTreeState(*viewport, c0(), e0()), -1234, -567,
      gfx::Rect(0, 0, 800, 600), gfx::Size(2400, 1800));
  auto* fixed_transform = CreateFixedPositionTranslation(
      *viewport, 100, 200, scroll_state1.Transform());
  PropertyTreeState fixed_state(*fixed_transform, scroll_state1.Clip(), e0());

  // A visual rect (0, 0, 100, 100) under fixed_transform (with a (100, 200)
  // 2d translation) is expanded to (100, 200, 100 + 2400 -800, 100 + 1800 -600)
  // which is (100, 200, 1700, 1300) in the scrolling space.
  {
    SCOPED_TRACE("fixed_state and scroll_state1");
    CheckOverlap(gfx::RectF(0, 0, 100, 100), fixed_state,
                 gfx::RectF(100, 200, 1700, 1300), scroll_state1);
  }

  {
    SCOPED_TRACE("fixed_state and scroll_state2");
    auto scroll_state2 = CreateScrollTranslationState(
        scroll_state1, -2345, -678, gfx::Rect(20, 10, 200, 100),
        gfx::Size(3000, 2000));
    // The result is false because the container rect of scroll_state2 doesn't
    // intersect with the expanded fixed-position rect in scroll_state1.
    EXPECT_FALSE(MightOverlapForCompositing(gfx::RectF(0, 0, 100, 100),
                                            fixed_state, gfx::RectF(1, 2, 3, 4),
                                            scroll_state2));
    EXPECT_FALSE(MightOverlapForCompositing(
        gfx::RectF(0, 0, 100, 100), fixed_state, gfx::RectF(0, 0, 1000, 1000),
        scroll_state2));
  }
  {
    SCOPED_TRACE("fixed_state and scroll_state3");
    auto scroll_state3 = CreateScrollTranslationState(
        scroll_state1, -234, -567, gfx::Rect(0, 300, 500, 500),
        gfx::Size(1000, 2000));
    EXPECT_FALSE(MightOverlapForCompositing(gfx::RectF(0, 0, 100, 100),
                                            fixed_state, gfx::RectF(1, 2, 3, 4),
                                            scroll_state3));
    EXPECT_TRUE(
        MightOverlapForCompositing(gfx::RectF(0, 0, 100, 100), fixed_state,
                                   gfx::RectF(0, 0, 500, 500), scroll_state3));
  }
}

TEST_P(GeometryMapperTest, MightOverlapFixedWithScale) {
  auto* viewport = CreateTransform(t0(), gfx::Transform());
  auto scroll_state = CreateScrollTranslationState(
      PropertyTreeState(*viewport, c0(), e0()), -1234, -567,
      gfx::Rect(0, 0, 800, 600), gfx::Size(2400, 1800));
  auto* fixed_transform = CreateFixedPositionTranslation(
      *viewport, 100, 200, scroll_state.Transform());
  auto* scale = CreateTransform(*fixed_transform, MakeScaleMatrix(2, 3));
  PropertyTreeState fixed_state(*scale, scroll_state.Clip(), e0());

  // Similar to the first case in MightOverlapFixed, but the fixed-position
  // visual rect is scaled first.
  CheckOverlap(gfx::RectF(0, 0, 100, 100), fixed_state,
               gfx::RectF(100, 200, 1800, 1500), scroll_state);
}

TEST_P(GeometryMapperTest, MightOverlapWithScrollingClip) {
  auto* viewport = CreateTransform(t0(), gfx::Transform());
  auto scroll_state = CreateScrollTranslationState(
      PropertyTreeState(*viewport, c0(), e0()), -1234, -567,
      gfx::Rect(0, 0, 800, 600), gfx::Size(2400, 1800));
  auto* fixed_transform = CreateFixedPositionTranslation(
      *viewport, 100, 200, scroll_state.Transform());
  auto* scrolling_clip =
      CreateClip(scroll_state.Clip(), scroll_state.Transform(),
                 FloatRoundedRect(0, 1000, 100, 100));
  PropertyTreeState fixed_state(*fixed_transform, *scrolling_clip, e0());

  // Same as the first case in MightOverlapFixed. The scrolling clip is ignored.
  CheckOverlap(gfx::RectF(0, 0, 100, 100), fixed_state,
               gfx::RectF(100, 200, 1700, 1300), scroll_state);
}

TEST_P(GeometryMapperTest, MightOverlapWithScrollingClipAndScale) {
  auto* viewport = CreateTransform(t0(), gfx::Transform());
  auto scroll_state = CreateScrollTranslationState(
      PropertyTreeState(*viewport, c0(), e0()), -1234, -567,
      gfx::Rect(0, 0, 800, 600), gfx::Size(2400, 1800));
  auto* fixed_transform = CreateFixedPositionTranslation(
      *viewport, 100, 200, scroll_state.Transform());
  auto* scale = CreateTransform(*fixed_transform, MakeScaleMatrix(2, 3));
  auto* scrolling_clip =
      CreateClip(scroll_state.Clip(), scroll_state.Transform(),
                 FloatRoundedRect(0, 1000, 100, 100));
  PropertyTreeState fixed_state(*scale, *scrolling_clip, e0());

  // Same as MightOverlapFixedWithScale. The scrolling clip is ignored.
  CheckOverlap(gfx::RectF(0, 0, 100, 100), fixed_state,
               gfx::RectF(100, 200, 1800, 1500), scroll_state);
}

TEST_P(GeometryMapperTest, MightOverlapScroll) {
  auto* viewport = CreateTransform(t0(), gfx::Transform());
  // The scroll offsets are arbitrary and should not affect the test result.
  auto outer_scroll_state = CreateScrollTranslationState(
      PropertyTreeState(*viewport, c0(), e0()), -1234, -567,
      gfx::Rect(10, 20, 100, 200), gfx::Size(150, 300));
  auto inner_scroll_state = CreateScrollTranslationState(
      outer_scroll_state, -2345, -678, gfx::Rect(20, 10, 200, 100),
      gfx::Size(3000, 2000));

  auto* transform_outside = Create2DTranslation(*viewport, 100, 200);
  PropertyTreeState state_outside(*transform_outside, c0(), e0());

  auto* transform_under_outer_scroll =
      Create2DTranslation(outer_scroll_state.Transform(), 34, 56);
  PropertyTreeState state_under_outer_scroll(*transform_under_outer_scroll,
                                             outer_scroll_state.Clip(),
                                             outer_scroll_state.Effect());

  auto* transform_under_inner_scroll =
      Create2DTranslation(inner_scroll_state.Transform(), 45, 67);
  PropertyTreeState state_under_inner_scroll(*transform_under_inner_scroll,
                                             inner_scroll_state.Clip(),
                                             inner_scroll_state.Effect());

  // For any rect directly or indirectly under outer_scroll_state, we should
  // use the rect mapped for scroll to check overlap with any rect outside of
  // the outer_scroll_state. The mapped rect of the following rect is defined
  // in each SCOPED_TRACE() block.
  gfx::RectF rect(70, 80, 3, 4);

  {
    SCOPED_TRACE("outer_scroll_state and state_outside");
    // `rect` is expanded for scroll offset: (20, -20, 53, 104),
    // clipped by the container rect: (20, 20, 53, 64),
    EXPECT_EQ(gfx::RectF(20, 20, 53, 64),
              MapVisualRectAboveScrollForCompositingOverlap(
                  outer_scroll_state.Transform(), rect, outer_scroll_state));
    // Then mapped into state_outside. Other rects in other
    // SCOPED_TRACE() blocks are computed similarly.
    gfx::RectF rect_mapped_in_state_outside(-80, -180, 53, 64);
    CheckOverlap(rect, outer_scroll_state, rect_mapped_in_state_outside,
                 state_outside);
  }
  {
    // The difference from the first case is that `rect` is mapped with the
    // local transform into the scrolling contents space first.
    SCOPED_TRACE("state_under_outer_scroll and state_outside");
    EXPECT_EQ(
        gfx::RectF(54, 36, 53, 104),
        MapVisualRectAboveScrollForCompositingOverlap(
            outer_scroll_state.Transform(), rect, state_under_outer_scroll));
    CheckOverlap(rect, state_under_outer_scroll, gfx::RectF(-46, -164, 53, 104),
                 state_outside);
  }
  {
    // `rect` is mapped through two scroll translations.
    SCOPED_TRACE("inner_scroll_state and state_outside");
    CheckOverlap(rect, inner_scroll_state, gfx::RectF(-90, -180, 63, 64),
                 state_outside);
  }
  {
    // `rect` is mapped by local transform, then through two scroll
    // translations.
    SCOPED_TRACE("state_under_inner_scroll and state_outside");
    CheckOverlap(rect, state_under_inner_scroll, gfx::RectF(-90, -180, 100, 90),
                 state_outside);
  }
  {
    SCOPED_TRACE("inner_scroll_state and outer_scroll_state");
    CheckOverlap(rect, inner_scroll_state, gfx::RectF(20, 20, 53, 64),
                 outer_scroll_state);
  }
  {
    SCOPED_TRACE("state_under_inner_scroll and outer_scroll_state");
    CheckOverlap(rect, state_under_inner_scroll, gfx::RectF(20, 20, 98, 90),
                 outer_scroll_state);
  }
  {
    SCOPED_TRACE("state_under_inner_scroll and state_under_outer_scroll");
    CheckOverlap(rect, state_under_inner_scroll, gfx::RectF(-14, -36, 98, 90),
                 state_under_outer_scroll);
  }
}

}  // namespace blink
```