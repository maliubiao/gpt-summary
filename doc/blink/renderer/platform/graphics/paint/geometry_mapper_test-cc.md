Response:
The user wants to understand the functionality of the `geometry_mapper_test.cc` file in the Chromium Blink engine. They are interested in:

1. **General functionality:** What does this test file do?
2. **Relationship to web technologies:** How does it relate to JavaScript, HTML, and CSS?
3. **Logical reasoning:** What are some example inputs and outputs of the code being tested?
4. **Common user errors:** What mistakes might developers make when using the tested code?
5. **Summary of functionality:** A concise overview of what the file does, considering this is the first of two parts.

Based on the file content, the core functionality revolves around testing the `GeometryMapper` class. This class is likely responsible for calculating and manipulating geometric transformations and clipping regions within the rendering pipeline.

**Functionality Breakdown:**

*   **Testing geometric mappings:** The numerous `TEST_P` functions (e.g., `Root`, `IdentityTransform`, `TranslationTransform`, etc.) strongly suggest that the file tests various scenarios involving geometric transformations like translation, rotation, scaling, and combinations thereof.
*   **Testing clipping:** Several tests focus on `ClipPaintPropertyNode` and how clipping regions are applied and transformed.
*   **Testing visual rect calculations:** Functions like `LocalToAncestorVisualRectInternal` indicate the file tests how the visible area of an element is determined in relation to its ancestors, considering transformations and clips.
*   **Testing overlap detection:** The `MightOverlapForCompositing` function suggests tests for determining if two rectangular areas might overlap, which is crucial for compositing optimizations.
*   **Testing caching of clip information:** The `CheckCachedClip` function implies testing a mechanism for caching computed clip regions to improve performance.

**Relationship to JavaScript, HTML, and CSS:**

*   **CSS Transforms:** The tests directly involve manipulating transformations, which are heavily used in CSS via the `transform` property. For example, CSS like `transform: rotate(45deg) scale(2);` would be related to tests like `RotationAndScaleTransform`.
*   **CSS Clipping:** The tests involving `ClipPaintPropertyNode` relate directly to the CSS `clip-path` and `clip` properties, which define what parts of an element are visible.
*   **Layout and Rendering:** The calculations performed by `GeometryMapper` are fundamental to how the browser lays out and renders web pages. Changes in HTML structure or CSS styles that affect element positioning, transformations, or clipping will involve these calculations. For example, changing the `position` of an element or adding a `overflow: hidden` style would trigger the logic being tested here.
*   **Compositing:** The overlap tests are directly related to browser compositing. When certain conditions are met (e.g., use of transforms, opacity, or filters), the browser can composite elements onto separate layers to improve rendering performance. Determining potential overlaps is crucial for deciding when and how to composite.

**Logical Reasoning (Hypothetical Examples):**

*   **Input:** A div with `transform: translateX(10px);` and a child div at position (0, 0) with size 50x50.
    *   **Output (for `LocalToAncestorVisualRectInternal`):** The child div's visual rect in the parent's coordinate system would be (10, 0, 50, 50).
*   **Input:** Two divs with no transformations or clipping, one at (0, 0) with size 100x100, the other at (50, 50) with size 100x100.
    *   **Output (for `MightOverlapForCompositing`):**  The function would return `true`.
*   **Input:** A div with `clip-path: circle(50px);` and a child div whose bounds extend beyond the circle.
    *   **Output (for `LocalToAncestorClipRect`):** The resulting clip rect would represent the circular area.

**Common User/Programming Errors:**

*   **Incorrect Transform Order:** When combining multiple transforms in CSS, the order matters. A developer might mistakenly apply transformations in the wrong sequence, leading to unexpected visual results. The tests for `NestedTransformsScaleAndTranslation` address this.
*   **Misunderstanding Clipping Contexts:** Developers might not fully grasp how nested clipping paths or transformations interact, leading to elements being clipped unexpectedly or not clipped when intended. The tests for `TwoClips` and `TwoClipsWithTransformBetween` are relevant here.
*   **Forgetting Transform Origins:** When applying rotations or scaling, the `transform-origin` property is crucial. Forgetting to set it or setting it incorrectly can lead to elements transforming around the wrong point. The test for `RotationAndScaleTransformWithTransformOrigin` highlights this.

**Summary of Functionality (Part 1):**

This test file for `geometry_mapper_test.cc` focuses on verifying the correctness of the `GeometryMapper` class in Blink. It comprehensively tests how the browser calculates and applies geometric transformations and clipping operations in various scenarios, including single and nested transformations, different types of clips, and combinations of both. The tests ensure that the visual representation of elements is accurately determined, which is fundamental to proper web page rendering. The file also includes tests for compositing-related overlap detection and caching mechanisms for performance optimization.

这是文件 `blink/renderer/platform/graphics/paint/geometry_mapper_test.cc` 的第一部分，它主要的功能是 **测试 `GeometryMapper` 类的各种几何映射和计算功能**。`GeometryMapper` 类在 Blink 渲染引擎中负责执行坐标空间之间的转换、计算元素的可见区域（visual rect）以及处理裁剪（clipping）操作。

具体来说，从代码中可以看出，这个测试文件涵盖了以下几个核心功能：

1. **局部坐标到祖先坐标的视觉矩形映射 (Local to Ancestor Visual Rect):** 测试如何将一个元素在其自身坐标系中的矩形区域映射到其祖先元素的坐标系中，考虑了变换 (transform) 和裁剪 (clip) 的影响。这与 CSS 中的 `transform` 属性以及各种裁剪属性（如 `clip-path`，`overflow: hidden` 等）密切相关。

    *   **举例说明:** 假设一个 HTML 元素 A 内部有一个子元素 B，元素 A 应用了 `transform: translateX(10px);`，元素 B 相对于元素 A 的位置是 `left: 0; top: 0;`，尺寸是 `50px * 50px`。`LocalToAncestorVisualRect` 的测试会验证，当计算元素 B 在页面根元素坐标系中的视觉矩形时，是否正确地加上了元素 A 的偏移量，得到 `(10, 0, 50, 50)`。
    *   **假设输入与输出:**
        *   **假设输入:** `input_rect` 为子元素 B 在其自身坐标系中的矩形 `(0, 0, 50, 50)`，`local_transform` 代表元素 A 的 `translateX(10px)` 变换，`ancestor_transform` 为根元素的单位变换。
        *   **预期输出:** `expected_visual_rect` 为 `(10, 0, 50, 50)`。

2. **局部坐标到祖先坐标的裁剪矩形映射 (Local to Ancestor Clip Rect):** 测试如何将一个元素上的裁剪区域映射到其祖先元素的坐标系中。这与 CSS 中的裁剪属性直接对应。

    *   **举例说明:** 假设一个 HTML 元素 C 应用了 `overflow: hidden;` 并设定了宽高为 `100px * 100px`。`LocalToAncestorClipRect` 的测试会验证，当计算其裁剪区域在页面根元素坐标系中的表示时，是否正确地得到了一个 `(x, y, 100, 100)` 的矩形。
    *   **假设输入与输出:**
        *   **假设输入:** `local_clip` 代表元素 C 的裁剪区域 `(0, 0, 100, 100)`。
        *   **预期输出:** `expected_clip` 为 `(0, 0, 100, 100)` (假设元素 C 没有其他变换)。

3. **源矩形到目标矩形的变换 (Source to Destination Rect):** 测试如何将一个坐标空间中的矩形变换到另一个坐标空间中，只考虑变换的影响，不考虑裁剪。这直接关联到 CSS 的 `transform` 属性。

    *   **举例说明:** 假设一个 HTML 元素 D 应用了 `transform: rotate(45deg);`。`SourceToDestinationRect` 的测试会验证，将元素 D 自身坐标系中的一个矩形 (比如 `(0, 0, 50, 50)`) 变换到父元素坐标系时，是否按照旋转 45 度的规则进行了正确的计算。
    *   **假设输入与输出:**
        *   **假设输入:** `input_rect` 为 `(0, 0, 50, 50)`，`local_transform` 代表旋转 45 度的变换。
        *   **预期输出:** `expected_transformed_rect` 为 `input_rect` 旋转 45 度后的矩形。

4. **源投影到目标投影 (Source to Destination Projection):** 测试计算从一个坐标空间到另一个坐标空间的变换矩阵。

    *   **举例说明:**  如果元素 E 的变换是 `translateX(20px)`，`SourceToDestinationProjection` 的测试会验证生成的变换矩阵是否表示向 X 轴平移 20 像素。

5. **裁剪缓存 (Cached Clip):** 测试 `GeometryMapper` 中用于缓存裁剪信息的机制。这是一种性能优化手段，避免重复计算相同的裁剪区域。

6. **重叠判断 (MightOverlapForCompositing):** 测试判断两个矩形在各自的坐标空间经过变换后是否可能重叠。这与浏览器合成 (compositing) 优化相关。

    *   **举例说明:** 假设两个 HTML 元素分别在不同的层上，各自应用了不同的变换。`MightOverlapForCompositing` 的测试会验证，即使这两个元素在初始布局上不重叠，但经过变换后可能会发生重叠的情况能否被正确检测出来。
    *   **假设输入与输出:**
        *   **假设输入:** `rect1` 和 `state1` 代表元素 F 的矩形和变换状态，`rect2` 和 `state2` 代表元素 G 的矩形和变换状态，元素 F 应用了 `translateX(50px)`，元素 G 没有变换，初始位置使得它们在 X 轴方向上相邻。
        *   **预期输出:** 如果元素 F 的初始 X 坐标为 0，宽度为 100，元素 G 的初始 X 坐标为 100，宽度为 100，则 `MightOverlapForCompositing` 应该返回 `false`。如果元素 F 的初始 X 坐标为 60，则返回 `true`。

**与 JavaScript, HTML, CSS 的关系:**

这个测试文件直接测试的是 Blink 渲染引擎中处理视觉效果的核心逻辑，这些视觉效果通常由 HTML 结构和 CSS 样式定义。

*   **HTML:**  HTML 定义了页面的结构，元素之间的层级关系会影响坐标空间的继承。
*   **CSS:**  CSS 提供了控制元素视觉表现的各种属性，包括 `transform` (定义元素的变换效果)，`clip-path` 和 `clip` (定义元素的裁剪区域)，`overflow` (控制内容溢出时的裁剪行为) 等。这些 CSS 属性的效果就是通过 `GeometryMapper` 及其相关类来实现的。
*   **JavaScript:** 虽然这个测试文件本身不直接涉及 JavaScript，但 JavaScript 可以动态修改元素的 CSS 属性，从而间接地影响 `GeometryMapper` 的行为。例如，通过 JavaScript 修改元素的 `transform` 属性会触发 `GeometryMapper` 重新计算元素的视觉矩形。

**用户或编程常见的使用错误:**

*   **CSS `transform` 属性使用错误:**  比如错误地组合多个 `transform` 函数，导致元素变换效果不符合预期。
*   **CSS 裁剪属性理解错误:**  比如对 `clip-path` 的坐标系统理解有误，导致裁剪区域不正确。
*   **在复杂的变换和裁剪场景下，手动计算元素的最终位置或可见区域可能会出错。** `GeometryMapper` 的作用就是自动且准确地完成这些计算。

**总结 (第 1 部分的功能):**

`geometry_mapper_test.cc` (第 1 部分) 的主要功能是全面测试 Blink 渲染引擎中 `GeometryMapper` 类的核心几何映射和计算能力。它涵盖了坐标空间转换、视觉矩形计算、裁剪处理、变换应用以及重叠判断等关键功能，这些功能直接支撑着网页元素的渲染和视觉效果的呈现。测试用例覆盖了各种变换、裁剪的组合场景，旨在确保 `GeometryMapper` 在处理由 HTML 和 CSS 定义的视觉效果时能够准确无误。

### 提示词
```
这是目录为blink/renderer/platform/graphics/paint/geometry_mapper_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/graphics/paint/geometry_mapper.h"
#include "build/build_config.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/graphics/box_reflection.h"
#include "third_party/blink/renderer/platform/graphics/filters/paint_filter_builder.h"
#include "third_party/blink/renderer/platform/graphics/paint/clip_paint_property_node.h"
#include "third_party/blink/renderer/platform/graphics/paint/effect_paint_property_node.h"
#include "third_party/blink/renderer/platform/graphics/paint/transform_paint_property_node.h"
#include "third_party/blink/renderer/platform/testing/paint_property_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/paint_test_configurations.h"
#include "ui/gfx/geometry/test/geometry_util.h"

namespace blink {

class GeometryMapperTest : public testing::Test,
                           public PaintTestConfigurations {
 public:
  const GeometryMapperClipCache::ClipCacheEntry* GetCachedClip(
      const ClipPaintPropertyNode& descendant_clip,
      const PropertyTreeState& ancestor_property_tree_state) {
    GeometryMapperClipCache::ClipAndTransform clip_and_transform(
        &ancestor_property_tree_state.Clip(),
        &ancestor_property_tree_state.Transform(), kIgnoreOverlayScrollbarSize);
    return descendant_clip.GetClipCache().GetCachedClip(clip_and_transform);
  }

  static void LocalToAncestorVisualRectInternal(
      const PropertyTreeStateOrAlias& local,
      const PropertyTreeStateOrAlias& ancestor,
      FloatClipRect& mapping_rect) {
    GeometryMapper::LocalToAncestorVisualRectInternalForTesting(
        local.Unalias(), ancestor.Unalias(), mapping_rect);
  }

  static void LocalToAncestorVisualRectForCompositingOverlap(
      const PropertyTreeStateOrAlias& local,
      const PropertyTreeStateOrAlias& ancestor,
      FloatClipRect& mapping_rect) {
    GeometryMapper::
        LocalToAncestorVisualRectInternalForCompositingOverlapForTesting(
            local.Unalias(), ancestor.Unalias(), mapping_rect);
  }

  static bool MightOverlapForCompositing(const gfx::RectF& rect1,
                                         const PropertyTreeState& state1,
                                         const gfx::RectF& rect2,
                                         const PropertyTreeState& state2) {
    bool result = GeometryMapper::MightOverlapForCompositing(rect1, state1,
                                                             rect2, state2);
    EXPECT_EQ(result, GeometryMapper::MightOverlapForCompositing(
                          rect2, state2, rect1, state1));
    return result;
  }

  static gfx::RectF MapVisualRectAboveScrollForCompositingOverlap(
      const TransformPaintPropertyNode& scroll_translation,
      const gfx::RectF& rect,
      const PropertyTreeState& state) {
    PropertyTreeState new_state = state;
    gfx::RectF new_rect = rect;
    GeometryMapper::MapVisualRectAboveScrollForCompositingOverlap(
        scroll_translation, new_rect, new_state);
    EXPECT_EQ(&new_state.Transform(), scroll_translation.UnaliasedParent());
    EXPECT_EQ(
        &new_state.Clip(),
        scroll_translation.ScrollNode()->OverflowClipNode()->UnaliasedParent());
    return new_rect;
  }

  // For any rect |r|, MightOverlapForCompositing(rect1, state1, r, state2) is
  // expected to be true iff |r| intersects |rect2| in |state2|.
  void CheckOverlap(const gfx::RectF& rect1,
                    const PropertyTreeState& state1,
                    const gfx::RectF& rect2,
                    const PropertyTreeState& state2);

  void CheckMappings();
  void CheckLocalToAncestorVisualRect();
  void CheckLocalToAncestorClipRect();
  void CheckSourceToDestinationRect();
  void CheckSourceToDestinationProjection();
  void CheckCachedClip();

  PropertyTreeStateOrAlias LocalState() const {
    return PropertyTreeStateOrAlias(*local_transform, *local_clip,
                                    *local_effect);
  }
  PropertyTreeStateOrAlias AncestorState() const {
    return PropertyTreeStateOrAlias(*ancestor_transform, *ancestor_clip,
                                    *ancestor_effect);
  }

  // Variables required by CheckMappings(). The tests should set these
  // variables with proper values before calling CheckMappings().
  Persistent<const TransformPaintPropertyNodeOrAlias> local_transform =
      &TransformPaintPropertyNode::Root();
  Persistent<const ClipPaintPropertyNodeOrAlias> local_clip =
      &ClipPaintPropertyNode::Root();
  Persistent<const EffectPaintPropertyNodeOrAlias> local_effect =
      &EffectPaintPropertyNode::Root();
  Persistent<const TransformPaintPropertyNodeOrAlias> ancestor_transform =
      &TransformPaintPropertyNode::Root();
  Persistent<const ClipPaintPropertyNodeOrAlias> ancestor_clip =
      &ClipPaintPropertyNode::Root();
  Persistent<const EffectPaintPropertyNodeOrAlias> ancestor_effect =
      &EffectPaintPropertyNode::Root();
  gfx::RectF input_rect;
  FloatClipRect expected_visual_rect;
  std::optional<FloatClipRect> expected_visual_rect_expanded_for_compositing;
  gfx::Vector2dF expected_translation_2d;
  std::optional<gfx::Transform> expected_transform;
  FloatClipRect expected_clip;
  bool expected_clip_has_transform_animation = false;
  bool expected_clip_has_sticky_transform = false;
  gfx::RectF expected_transformed_rect;
};

INSTANTIATE_PAINT_TEST_SUITE_P(GeometryMapperTest);

#define EXPECT_CLIP_RECT_NEAR(expected, actual, tolerance)                \
  do {                                                                    \
    SCOPED_TRACE("EXPECT_CLIP_RECT_EQ: " #expected " vs " #actual);       \
    EXPECT_EQ((expected).IsInfinite(), (actual).IsInfinite());            \
    EXPECT_EQ((expected).HasRadius(), (actual).HasRadius());              \
    EXPECT_EQ((expected).IsTight(), (actual).IsTight());                  \
    if (!(expected).IsInfinite())                                         \
      EXPECT_RECTF_NEAR((expected).Rect(), (actual).Rect(), (tolerance)); \
  } while (false)

#define EXPECT_CLIP_RECT_EQ(expected, actual) \
  EXPECT_CLIP_RECT_NEAR(expected, actual, 0)

void GeometryMapperTest::CheckLocalToAncestorVisualRect() {
  FloatClipRect actual_visual_rect(input_rect);
  LocalToAncestorVisualRectInternal(LocalState(), AncestorState(),
                                    actual_visual_rect);
  EXPECT_CLIP_RECT_EQ(expected_visual_rect, actual_visual_rect);

  actual_visual_rect = FloatClipRect(input_rect);
  LocalToAncestorVisualRectForCompositingOverlap(LocalState(), AncestorState(),
                                                 actual_visual_rect);
  EXPECT_CLIP_RECT_EQ(expected_visual_rect_expanded_for_compositing
                          ? *expected_visual_rect_expanded_for_compositing
                          : expected_visual_rect,
                      actual_visual_rect);
}

void GeometryMapperTest::CheckLocalToAncestorClipRect() {
  FloatClipRect actual_clip_rect =
      GeometryMapper::LocalToAncestorClipRect(LocalState(), AncestorState());
  EXPECT_CLIP_RECT_EQ(expected_clip, actual_clip_rect);
}

void GeometryMapperTest::CheckSourceToDestinationRect() {
  auto actual_transformed_rect = input_rect;
  GeometryMapper::SourceToDestinationRect(*local_transform, *ancestor_transform,
                                          actual_transformed_rect);
  EXPECT_EQ(expected_transformed_rect, actual_transformed_rect);
}

void GeometryMapperTest::CheckSourceToDestinationProjection() {
  gfx::Transform projection = GeometryMapper::SourceToDestinationProjection(
      *local_transform, *ancestor_transform);
  if (expected_transform) {
    EXPECT_EQ(*expected_transform, projection);
  } else {
    EXPECT_TRUE(projection.IsIdentityOr2dTranslation());
    EXPECT_EQ(expected_translation_2d, projection.To2dTranslation());
  }
}

void GeometryMapperTest::CheckCachedClip() {
  if (ancestor_effect != local_effect) {
    return;
  }
  const auto& unaliased_local_clip = local_clip->Unalias();
  const auto* cached_clip =
      GetCachedClip(unaliased_local_clip, AncestorState().Unalias());
  if (ancestor_clip == &unaliased_local_clip ||
      (ancestor_clip == unaliased_local_clip.Parent() &&
       ancestor_transform == &unaliased_local_clip.LocalTransformSpace())) {
    EXPECT_EQ(nullptr, cached_clip);
    return;
  }
  ASSERT_NE(nullptr, cached_clip);
  EXPECT_CLIP_RECT_EQ(expected_clip, cached_clip->clip_rect);
  EXPECT_EQ(expected_clip_has_transform_animation,
            cached_clip->has_transform_animation);
  EXPECT_EQ(expected_clip_has_sticky_transform,
            cached_clip->has_sticky_transform);
}

// See the data fields of GeometryMapperTest for variables that will be used in
// this function.
void GeometryMapperTest::CheckMappings() {
  CheckLocalToAncestorVisualRect();
  CheckLocalToAncestorClipRect();
  CheckSourceToDestinationRect();
  CheckSourceToDestinationProjection();
  {
    SCOPED_TRACE("Repeated check to test caching");
    CheckLocalToAncestorVisualRect();
    CheckLocalToAncestorClipRect();
    CheckSourceToDestinationRect();
    CheckSourceToDestinationProjection();
  }
  CheckCachedClip();
}

// Checks rect1 in state1 and rect2 in state2 exactly overlap. Any point inside
// rect1 should overlap with rect2, and any point outside of rect1 should not
// overlap with rect2, and vice versa.
void GeometryMapperTest::CheckOverlap(const gfx::RectF& rect1,
                                      const PropertyTreeState& state1,
                                      const gfx::RectF& rect2,
                                      const PropertyTreeState& state2) {
  // How to debug: If anything fail, keep only the following line, and examine
  // whether the two visual rects from VisualRectForCompositingOverlap() are
  // equal. If not, examine the test data and GeometryMapper code.
  EXPECT_TRUE(MightOverlapForCompositing(rect1, state1, rect2, state2));

  // Test four 1x1 rects around each corner.
  gfx::RectF top_left(rect2.origin(), gfx::SizeF(1, 1));
  EXPECT_TRUE(MightOverlapForCompositing(rect1, state1, top_left, state2));
  EXPECT_FALSE(MightOverlapForCompositing(
      rect1, state1, top_left - gfx::Vector2dF(1, 0), state2));
  EXPECT_FALSE(MightOverlapForCompositing(
      rect1, state1, top_left - gfx::Vector2dF(1, 1), state2));
  EXPECT_FALSE(MightOverlapForCompositing(
      rect1, state1, top_left - gfx::Vector2dF(0, 1), state2));

  gfx::RectF top_right(rect2.top_right(), gfx::SizeF(1, 1));
  EXPECT_FALSE(MightOverlapForCompositing(rect1, state1, top_right, state2));
  EXPECT_TRUE(MightOverlapForCompositing(
      rect1, state1, top_right - gfx::Vector2dF(1, 0), state2));
  EXPECT_FALSE(MightOverlapForCompositing(
      rect1, state1, top_right - gfx::Vector2dF(1, 1), state2));
  EXPECT_FALSE(MightOverlapForCompositing(
      rect1, state1, top_right - gfx::Vector2dF(0, 1), state2));

  gfx::RectF bottom_right(rect2.bottom_right(), gfx::SizeF(1, 1));
  EXPECT_FALSE(MightOverlapForCompositing(rect1, state1, bottom_right, state2));
  EXPECT_FALSE(MightOverlapForCompositing(
      rect1, state1, bottom_right - gfx::Vector2dF(1, 0), state2));
  EXPECT_TRUE(MightOverlapForCompositing(
      rect1, state1, bottom_right - gfx::Vector2dF(1, 1), state2));
  EXPECT_FALSE(MightOverlapForCompositing(
      rect1, state1, bottom_right - gfx::Vector2dF(0, 1), state2));

  gfx::RectF bottom_left(rect2.bottom_left(), gfx::SizeF(1, 1));
  EXPECT_FALSE(MightOverlapForCompositing(rect1, state1, bottom_left, state2));
  EXPECT_FALSE(MightOverlapForCompositing(
      rect1, state1, bottom_left - gfx::Vector2dF(1, 0), state2));
  EXPECT_FALSE(MightOverlapForCompositing(
      rect1, state1, bottom_left - gfx::Vector2dF(1, 1), state2));
  EXPECT_TRUE(MightOverlapForCompositing(
      rect1, state1, bottom_left - gfx::Vector2dF(0, 1), state2));
}

TEST_P(GeometryMapperTest, Root) {
  input_rect = gfx::RectF(0, 0, 100, 100);
  expected_visual_rect = FloatClipRect(input_rect);
  expected_transformed_rect = input_rect;
  CheckMappings();
}

TEST_P(GeometryMapperTest, IdentityTransform) {
  local_transform = Create2DTranslation(t0(), 0, 0);

  input_rect = gfx::RectF(0, 0, 100, 100);
  expected_transformed_rect = input_rect;
  expected_visual_rect = FloatClipRect(input_rect);
  CheckMappings();
}

TEST_P(GeometryMapperTest, TranslationTransform) {
  expected_translation_2d = gfx::Vector2dF(20, 10);
  local_transform = Create2DTranslation(t0(), 20, 10);

  input_rect = gfx::RectF(0, 0, 100, 100);
  expected_transformed_rect = input_rect;
  expected_transformed_rect.Offset(expected_translation_2d);
  expected_visual_rect = FloatClipRect(expected_transformed_rect);
  CheckMappings();

  gfx::RectF rect = expected_transformed_rect;
  GeometryMapper::SourceToDestinationRect(t0(), *local_transform, rect);
  EXPECT_EQ(input_rect, rect);
}

TEST_P(GeometryMapperTest, TranslationTransformWithAlias) {
  expected_translation_2d = gfx::Vector2dF(20, 10);
  auto* real_transform = Create2DTranslation(t0(), 20, 10);
  local_transform = TransformPaintPropertyNodeAlias::Create(*real_transform);

  input_rect = gfx::RectF(0, 0, 100, 100);
  expected_transformed_rect = input_rect;
  expected_transformed_rect.Offset(expected_translation_2d);
  expected_visual_rect = FloatClipRect(expected_transformed_rect);
  CheckMappings();

  gfx::RectF rect = expected_transformed_rect;
  GeometryMapper::SourceToDestinationRect(t0(), *local_transform, rect);
  EXPECT_EQ(input_rect, rect);
}

TEST_P(GeometryMapperTest, RotationAndScaleTransform) {
  expected_transform = MakeRotationMatrix(45);
  expected_transform->Scale(2, 2);
  local_transform = CreateTransform(t0(), *expected_transform);

  input_rect = gfx::RectF(0, 0, 100, 100);
  expected_transformed_rect = expected_transform->MapRect(input_rect);
  expected_visual_rect = FloatClipRect(expected_transformed_rect);
  expected_visual_rect.ClearIsTight();
  CheckMappings();
}

TEST_P(GeometryMapperTest, RotationAndScaleTransformWithAlias) {
  expected_transform = MakeRotationMatrix(45);
  expected_transform->Scale(2, 2);
  auto* real_transform = CreateTransform(t0(), *expected_transform);
  local_transform = TransformPaintPropertyNodeAlias::Create(*real_transform);

  input_rect = gfx::RectF(0, 0, 100, 100);
  expected_transformed_rect = expected_transform->MapRect(input_rect);
  expected_visual_rect = FloatClipRect(expected_transformed_rect);
  expected_visual_rect.ClearIsTight();
  CheckMappings();
}

TEST_P(GeometryMapperTest, RotationAndScaleTransformWithTransformOrigin) {
  expected_transform = MakeRotationMatrix(45);
  expected_transform->Scale(2, 2);
  local_transform =
      CreateTransform(t0(), *expected_transform, gfx::Point3F(50, 50, 0));

  input_rect = gfx::RectF(0, 0, 100, 100);
  expected_transform->ApplyTransformOrigin(50, 50, 0);
  expected_transformed_rect = expected_transform->MapRect(input_rect);
  expected_visual_rect = FloatClipRect(expected_transformed_rect);
  expected_visual_rect.ClearIsTight();
  CheckMappings();
}

TEST_P(GeometryMapperTest, NestedTransforms) {
  auto rotate_transform = MakeRotationMatrix(45);
  auto* transform1 = CreateTransform(t0(), rotate_transform);

  auto scale_transform = MakeScaleMatrix(2);
  local_transform = CreateTransform(*transform1, scale_transform);

  input_rect = gfx::RectF(0, 0, 100, 100);
  expected_transform = rotate_transform * scale_transform;
  expected_transformed_rect = expected_transform->MapRect(input_rect);
  expected_visual_rect = FloatClipRect(expected_transformed_rect);
  expected_visual_rect.ClearIsTight();
  CheckMappings();
}

TEST_P(GeometryMapperTest, NestedTransformsFlattening) {
  auto rotate_transform = MakeRotationMatrix(45, 0, 0);
  auto* transform1 = CreateTransform(t0(), rotate_transform);

  auto inverse_rotate_transform = MakeRotationMatrix(-45, 0, 0);
  TransformPaintPropertyNode::State inverse_state{{inverse_rotate_transform}};
  inverse_state.flattens_inherited_transform = true;
  local_transform =
      TransformPaintPropertyNode::Create(*transform1, std::move(inverse_state));

  input_rect = gfx::RectF(0, 0, 100, 100);
  rotate_transform.Flatten();
  expected_transform = rotate_transform * inverse_rotate_transform;
  expected_transform->Flatten();
  expected_transformed_rect = expected_transform->MapRect(input_rect);
  expected_visual_rect = FloatClipRect(expected_transformed_rect);
  expected_visual_rect.ClearIsTight();
  CheckMappings();
}

TEST_P(GeometryMapperTest, NestedTransformsScaleAndTranslation) {
  auto scale_transform = MakeScaleMatrix(2);
  auto* transform1 = CreateTransform(t0(), scale_transform);

  auto translate_transform = MakeTranslationMatrix(100, 0);
  local_transform = CreateTransform(*transform1, translate_transform);

  input_rect = gfx::RectF(0, 0, 100, 100);
  // Note: unlike NestedTransforms, the order of these transforms matters. This
  // tests correct order of matrix multiplication.
  expected_transform = scale_transform * translate_transform;
  expected_transformed_rect = expected_transform->MapRect(input_rect);
  expected_visual_rect = FloatClipRect(expected_transformed_rect);
  expected_visual_rect.ClearIsTight();
  CheckMappings();
}

TEST_P(GeometryMapperTest, NestedTransformsIntermediateDestination) {
  auto translate_transform = MakeTranslationMatrix(10, 20);
  ancestor_transform = CreateTransform(t0(), translate_transform);

  auto scale_transform = MakeScaleMatrix(3);
  local_transform = CreateTransform(*ancestor_transform, scale_transform);

  expected_transform = scale_transform;
  input_rect = gfx::RectF(0, 0, 100, 100);
  expected_transformed_rect = expected_transform->MapRect(input_rect);
  expected_visual_rect = FloatClipRect(expected_transformed_rect);
  expected_visual_rect.ClearIsTight();
  CheckMappings();
}

TEST_P(GeometryMapperTest, SimpleClip) {
  auto* clip = CreateClip(c0(), t0(), FloatRoundedRect(10, 10, 50, 50));
  local_clip = clip;

  input_rect = gfx::RectF(0, 0, 100, 100);
  expected_transformed_rect = input_rect;  // not clipped.
  expected_clip = clip->LayoutClipRect();
  expected_visual_rect = expected_clip;
  CheckMappings();
}

TEST_P(GeometryMapperTest, UsesLayoutClipRect) {
  auto* clip = CreateClip(c0(), t0(), gfx::RectF(10, 10, 50.5, 50.5),
                          FloatRoundedRect(10, 10, 50, 51));
  local_clip = clip;

  input_rect = gfx::RectF(0, 0, 100, 100);
  expected_transformed_rect = input_rect;  // not clipped.

  // GeometryMapper uses the LayoutClipRect.
  expected_clip = clip->LayoutClipRect();
  expected_visual_rect = expected_clip;
  CheckMappings();
}

TEST_P(GeometryMapperTest, SimpleClipWithAlias) {
  auto* real_clip = CreateClip(c0(), t0(), FloatRoundedRect(10, 10, 50, 50));
  auto* clip = ClipPaintPropertyNodeAlias::Create(*real_clip);
  local_clip = clip;

  input_rect = gfx::RectF(0, 0, 100, 100);
  expected_transformed_rect = input_rect;  // not clipped.
  expected_clip = clip->Unalias().LayoutClipRect();
  expected_visual_rect = expected_clip;
  CheckMappings();
}

TEST_P(GeometryMapperTest, SimpleClipOverlayScrollbars) {
  ClipPaintPropertyNode::State clip_state(t0(), gfx::RectF(10, 10, 50, 50),
                                          FloatRoundedRect(10, 10, 50, 50));
  clip_state.layout_clip_rect_excluding_overlay_scrollbars =
      FloatClipRect(gfx::RectF(10, 10, 45, 43));
  local_clip = ClipPaintPropertyNode::Create(c0(), std::move(clip_state));

  input_rect = gfx::RectF(0, 0, 100, 100);

  FloatClipRect actual_visual_rect(input_rect);
  GeometryMapper::LocalToAncestorVisualRect(
      LocalState(), AncestorState(), actual_visual_rect,
      kExcludeOverlayScrollbarSizeForHitTesting);
  EXPECT_CLIP_RECT_EQ(FloatClipRect(gfx::RectF(10, 10, 45, 43)),
                      actual_visual_rect);

  // Check that not passing kExcludeOverlayScrollbarSizeForHitTesting gives
  // a different result.
  actual_visual_rect = FloatClipRect(input_rect);
  GeometryMapper::LocalToAncestorVisualRect(LocalState(), AncestorState(),
                                            actual_visual_rect,
                                            kIgnoreOverlayScrollbarSize);
  EXPECT_CLIP_RECT_EQ(FloatClipRect(gfx::RectF(10, 10, 50, 50)),
                      actual_visual_rect);

  FloatClipRect actual_clip_rect = GeometryMapper::LocalToAncestorClipRect(
      LocalState(), AncestorState(), kExcludeOverlayScrollbarSizeForHitTesting);
  EXPECT_CLIP_RECT_EQ(FloatClipRect(gfx::RectF(10, 10, 45, 43)),
                      actual_clip_rect);

  // Check that not passing kExcludeOverlayScrollbarSizeForHitTesting gives
  // a different result.
  actual_clip_rect = GeometryMapper::LocalToAncestorClipRect(
      LocalState(), AncestorState(), kIgnoreOverlayScrollbarSize);
  EXPECT_CLIP_RECT_EQ(FloatClipRect(gfx::RectF(10, 10, 50, 50)),
                      actual_clip_rect);
}

TEST_P(GeometryMapperTest, SimpleClipInclusiveIntersect) {
  local_clip = CreateClip(c0(), t0(), FloatRoundedRect(10, 10, 50, 50));

  FloatClipRect actual_clip_rect(gfx::RectF(60, 10, 10, 10));
  GeometryMapper::LocalToAncestorVisualRect(
      LocalState(), AncestorState(), actual_clip_rect,
      kIgnoreOverlayScrollbarSize, kEdgeInclusive);
  EXPECT_CLIP_RECT_EQ(FloatClipRect(gfx::RectF(60, 10, 0, 10)),
                      actual_clip_rect);

  // Check that not passing kExcludeOverlayScrollbarSizeForHitTesting gives
  // a different result.
  actual_clip_rect.SetRect(gfx::RectF(60, 10, 10, 10));
  GeometryMapper::LocalToAncestorVisualRect(LocalState(), AncestorState(),
                                            actual_clip_rect);
  EXPECT_CLIP_RECT_EQ(FloatClipRect(gfx::RectF()), actual_clip_rect);
}

TEST_P(GeometryMapperTest, SimpleClipPlusOpacity) {
  local_clip = CreateClip(c0(), t0(), FloatRoundedRect(10, 10, 50, 50));
  local_effect = CreateOpacityEffect(e0(), 0.99);

  FloatClipRect actual_clip_rect(gfx::RectF(60, 10, 10, 10));
  auto intersects = GeometryMapper::LocalToAncestorVisualRect(
      LocalState(), AncestorState(), actual_clip_rect);

  EXPECT_TRUE(actual_clip_rect.Rect().IsEmpty());
  EXPECT_FALSE(intersects);
}

TEST_P(GeometryMapperTest, SimpleClipPlusOpacityInclusiveIntersect) {
  local_clip = CreateClip(c0(), t0(), FloatRoundedRect(10, 10, 50, 50));
  local_effect = CreateOpacityEffect(e0(), 0.99);

  FloatClipRect actual_clip_rect(gfx::RectF(10, 10, 10, 0));
  auto intersects = GeometryMapper::LocalToAncestorVisualRect(
      LocalState(), AncestorState(), actual_clip_rect,
      kIgnoreOverlayScrollbarSize, kEdgeInclusive);

  EXPECT_TRUE(actual_clip_rect.Rect().IsEmpty());
  EXPECT_TRUE(intersects);
}

TEST_P(GeometryMapperTest, RoundedClip) {
  FloatRoundedRect rect(gfx::RectF(10, 10, 50, 50),
                        FloatRoundedRect::Radii(gfx::SizeF(1, 1), gfx::SizeF(),
                                                gfx::SizeF(), gfx::SizeF()));
  auto* clip = CreateClip(c0(), t0(), rect);
  local_clip = clip;

  input_rect = gfx::RectF(0, 0, 100, 100);
  expected_transformed_rect = input_rect;
  expected_clip = clip->LayoutClipRect();
  EXPECT_TRUE(expected_clip.HasRadius());
  expected_visual_rect = expected_clip;
  CheckMappings();
}

TEST_P(GeometryMapperTest, ClipPath) {
  FloatRoundedRect rect(gfx::RectF(10, 10, 50, 50),
                        FloatRoundedRect::Radii(gfx::SizeF(1, 1), gfx::SizeF(),
                                                gfx::SizeF(), gfx::SizeF()));
  auto* clip = CreateClipPathClip(c0(), t0(), FloatRoundedRect(10, 10, 50, 50));
  local_clip = clip;

  input_rect = gfx::RectF(0, 0, 100, 100);
  expected_transformed_rect = input_rect;
  expected_clip = FloatClipRect(gfx::RectF(10, 10, 50, 50));
  expected_clip.ClearIsTight();
  expected_visual_rect = expected_clip;
  CheckMappings();
}

TEST_P(GeometryMapperTest, TwoClips) {
  FloatRoundedRect clip_rect1(
      gfx::RectF(10, 10, 30, 40),
      FloatRoundedRect::Radii(gfx::SizeF(1, 1), gfx::SizeF(), gfx::SizeF(),
                              gfx::SizeF()));

  auto* clip1 = CreateClip(c0(), t0(), clip_rect1);
  auto* clip2 = CreateClip(*clip1, t0(), FloatRoundedRect(10, 10, 50, 50));
  local_clip = clip2;

  input_rect = gfx::RectF(0, 0, 100, 100);
  expected_transformed_rect = input_rect;
  expected_clip = clip1->LayoutClipRect();
  EXPECT_TRUE(expected_clip.HasRadius());
  expected_visual_rect = expected_clip;
  CheckMappings();

  ancestor_clip = clip1;
  expected_clip = clip2->LayoutClipRect();
  expected_visual_rect = expected_clip;
  CheckMappings();
}

TEST_P(GeometryMapperTest, TwoClipsTransformAbove) {
  auto* transform = Create2DTranslation(t0(), 0, 0);

  FloatRoundedRect clip_rect1(
      gfx::RectF(10, 10, 50, 50),
      FloatRoundedRect::Radii(gfx::SizeF(1, 1), gfx::SizeF(), gfx::SizeF(),
                              gfx::SizeF()));

  auto* clip1 = CreateClip(c0(), *transform, clip_rect1);
  auto* clip2 =
      CreateClip(*clip1, *transform, FloatRoundedRect(10, 10, 30, 40));
  local_clip = clip2;

  input_rect = gfx::RectF(0, 0, 100, 100);
  expected_transformed_rect = input_rect;
  expected_clip = clip2->LayoutClipRect();
  expected_clip.SetHasRadius();
  expected_visual_rect = expected_clip;
  CheckMappings();

  expected_clip = clip1->LayoutClipRect();
  EXPECT_TRUE(expected_clip.HasRadius());
  local_clip = clip1;
  expected_visual_rect = expected_clip;
  CheckMappings();
}

TEST_P(GeometryMapperTest, ClipBeforeTransform) {
  expected_transform = MakeRotationMatrix(45);
  local_transform = CreateTransform(t0(), *expected_transform);
  auto* clip =
      CreateClip(c0(), *local_transform, FloatRoundedRect(10, 10, 50, 50));
  local_clip = clip;

  input_rect = gfx::RectF(0, 0, 100, 100);
  expected_visual_rect = FloatClipRect(input_rect);
  expected_visual_rect.Intersect(clip->LayoutClipRect());
  expected_visual_rect.Map(*expected_transform);
  EXPECT_FALSE(expected_visual_rect.IsTight());
  expected_clip = clip->LayoutClipRect();
  expected_clip.Map(*expected_transform);
  EXPECT_FALSE(expected_clip.IsTight());
  expected_transformed_rect = expected_transform->MapRect(input_rect);
  CheckMappings();
}

TEST_P(GeometryMapperTest, ExpandVisualRectWithClipBeforeAnimatingTransform) {
  expected_transform = MakeRotationMatrix(45);
  local_transform = CreateAnimatingTransform(t0(), *expected_transform);
  auto* clip =
      CreateClip(c0(), *local_transform, FloatRoundedRect(10, 10, 50, 50));
  local_clip = clip;

  input_rect = gfx::RectF(0, 0, 100, 100);
  expected_visual_rect = FloatClipRect(input_rect);
  expected_visual_rect.Intersect(clip->LayoutClipRect());
  expected_visual_rect.Map(*expected_transform);
  // The clip has animating transform, so it doesn't apply to the visual rect.
  expected_visual_rect_expanded_for_compositing = InfiniteLooseFloatClipRect();
  EXPECT_FALSE(expected_visual_rect.IsTight());
  expected_clip = clip->LayoutClipRect();
  expected_clip.Map(*expected_transform);
  EXPECT_FALSE(expected_clip.IsTight());
  expected_clip_has_transform_animation = true;
  expected_transformed_rect = expected_transform->MapRect(input_rect);
  CheckMappings();
}

TEST_P(GeometryMapperTest, ExpandVisualRectWithClipBeforeSticky) {
  expected_transform = MakeTranslationMatrix(0, 100);
  local_transform = CreateTransform(t0(), *expected_transform, gfx::Point3F(),
                                    CompositingReason::kStickyPosition);
  auto* clip =
      CreateClip(c0(), *local_transform, FloatRoundedRect(10, 10, 50, 50));
  local_clip = clip;

  input_rect = gfx::RectF(0, 0, 100, 100);
  expected_visual_rect = FloatClipRect(input_rect);
  expected_visual_rect.Intersect(clip->LayoutClipRect());
  expected_visual_rect.Map(*expected_transform);
  // The clip has sticky transform, so it doesn't apply to the visual rect.
  expected_visual_rect_expanded_for_compositing = InfiniteLooseFloatClipRect();
  EXPECT_TRUE(expected_visual_rect.IsTight());
  expected_clip = clip->LayoutClipRect();
  expected_clip.Map(*expected_transform);
  EXPECT_TRUE(expected_clip.IsTight());
  expected_clip_has_sticky_transform = true;
  expected_transformed_rect = expected_transform->MapRect(input_rect);
  CheckMappings();
}

TEST_P(GeometryMapperTest, ClipAfterTransform) {
  expected_transform = MakeRotationMatrix(45);
  local_transform = CreateTransform(t0(), *expected_transform);
  auto* clip = CreateClip(c0(), t0(), FloatRoundedRect(10, 10, 200, 200));
  local_clip = clip;

  input_rect = gfx::RectF(0, 0, 100, 100);
  expected_transformed_rect = expected_transform->MapRect(input_rect);
  expected_visual_rect = FloatClipRect(input_rect);
  expected_visual_rect.Map(*expected_transform);
  expected_visual_rect.Intersect(clip->LayoutClipRect());
  EXPECT_FALSE(expected_visual_rect.IsTight());
  expected_clip = clip->LayoutClipRect();
  EXPECT_TRUE(expected_clip.IsTight());
  CheckMappings();
}

TEST_P(GeometryMapperTest, ExpandVisualRectWithClipAfterAnimatingTransform) {
  expected_transform = MakeRotationMatrix(45);
  local_transform = CreateAnimatingTransform(t0(), *expected_transform);
  auto* clip = CreateClip(c0(), t0(), FloatRoundedRect(10, 10, 200, 200));
  local_clip = clip;

  input_rect = gfx::RectF(0, 0, 100, 100);
  expected_transformed_rect = expected_transform->MapRect(input_rect);
  expected_visual_rect = FloatClipRect(input_rect);
  expected_visual_rect.Map(*expected_transform);
  expected_visual_rect.Intersect(clip->LayoutClipRect());
  EXPECT_FALSE(expected_visual_rect.IsTight());
  expected_clip = clip->LayoutClipRect();
  EXPECT_TRUE(expected_clip.IsTight());
  // The visual rect is expanded first to infinity because of the transform
  // animation, then clipped by the clip.
  expected_visual_rect_expanded_for_compositing = expected_clip;
  expected_visual_rect_expanded_for_compositing->ClearIsTight();
  CheckMappings();
}

TEST_P(GeometryMapperTest, ExpandVisualRectWithClipAfterSticky) {
  expected_transform = MakeTranslationMatrix(0, 100);
  local_transform = CreateTransform(t0(), *expected_transform, gfx::Point3F(),
                                    CompositingReason::kStickyPosition);
  auto* clip = CreateClip(c0(), t0(), FloatRoundedRect(10, 10, 200, 200));
  local_clip = clip;

  input_rect = gfx::RectF(0, 0, 100, 100);
  expected_transformed_rect = expected_transform->MapRect(input_rect);
  expected_visual_rect = FloatClipRect(input_rect);
  expected_visual_rect.Map(*expected_transform);
  expected_visual_rect.Intersect(clip->LayoutClipRect());
  EXPECT_TRUE(expected_visual_rect.IsTight());
  expected_clip = clip->LayoutClipRect();
  EXPECT_TRUE(expected_clip.IsTight());
  // The visual rect is expanded first to infinity because of the sticky
  // transform, then clipped by the clip.
  expected_visual_rect_expanded_for_compositing = expected_clip;
  expected_visual_rect_expanded_for_compositing->ClearIsTight();
  CheckMappings();
}

TEST_P(GeometryMapperTest, TwoClipsWithTransformBetween) {
  auto* clip1 = CreateClip(c0(), t0(), FloatRoundedRect(10, 10, 200, 200));
  expected_transform = MakeRotationMatrix(45);
  local_transform = CreateTransform(t0(), *expected_transform);
  auto* clip2 =
      CreateClip(*clip1, *local_transform, FloatRoundedRect(10, 10, 200, 200));
  local_clip = clip2;

  input_rect = gfx::RectF(0, 0, 100, 100);
  expected_transformed_rect = expected_transform->MapRect(input_rect);

  expected_clip = clip2->LayoutClipRect();
  expected_clip.Map(*expected_transform);
  expected_clip.Intersect(clip1->LayoutClipRect());
  EXPECT_FALSE(expected_clip.IsTight());

  // All clips are performed in the space of the ancestor. In cases such as
  // this, this means the clip is not tight.
  expected_visual_rect = FloatClipRect(input_rect);
  expected_visual_rect.Map(*expected_transform);
  // Intersect with all clips between local and ancestor, independently mapped
  // to ancestor space.
  expected_visual_rect.Intersect(expected_clip);
  EXPECT_FALSE(expected_visual_rect.IsTight());
  CheckMappings();
}

TEST_P(GeometryMapperTest,
       ExpandVisualRectWithTwoClipsWithAnimatingTransformBetween) {
  auto* clip1 = CreateClip(c0(), t0(), FloatRoundedRect(10, 10, 200, 200));
  expected_transform = MakeRotationMatrix(45);
  local_transform = CreateAnimatingTransform(t0(), *expected_transform);
  auto* clip2 =
      CreateClip(*clip1, *local_transform, FloatRoundedRect(10, 10, 200, 200));
  local_clip = clip2;

  input_rect = gfx::RectF(0, 0, 100, 100);
  expected_transformed_rect = expected_transform->MapRect(input_rect);

  expected_clip = clip2->LayoutClipRect();
  expected_clip.Map(*expected_transform);
  expected_clip.Intersect(clip1->LayoutClipRect());
  EXPECT_FALSE(expected_clip.IsTight());
  expected_clip_has
```