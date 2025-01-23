Response:
My thinking process to analyze the `cull_rect_test.cc` file goes like this:

1. **Understand the Purpose:** The file name `cull_rect_test.cc` immediately suggests it's a unit test file for a class or functionality related to `CullRect`. The directory `blink/renderer/platform/graphics/paint/` further clarifies that this is part of the Blink rendering engine, dealing with graphics and painting, specifically within the paint phase.

2. **Identify the Tested Class:**  The `#include "third_party/blink/renderer/platform/graphics/paint/cull_rect.h"` confirms that the primary class under test is `CullRect`.

3. **Analyze the Test Structure:** The file uses the Google Test framework (`testing/gtest/include/gtest/gtest.h`). The `CullRectTest` class inherits from `testing::Test`, setting up the test fixture. Individual tests are defined using `TEST_F(CullRectTest, ...)`.

4. **Examine Individual Tests:** I'd go through each test case, understanding what aspect of `CullRect` it's verifying. I'd pay attention to the input values, the expected output (often asserted using `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ`), and the specific `CullRect` methods being called.

5. **Group Tests by Functionality:**  As I analyze the tests, I'd mentally group them based on the `CullRect` methods or concepts they cover. For example:
    * Intersection tests (`IntersectsRect`, `IntersectsTransformed`)
    * Basic properties (`Infinite`)
    * Transformation methods (`Move`, `ApplyTransform`, `ApplyScrollTranslation`, `ApplyPaintProperties`)
    * Change detection (`ChangedEnough`)

6. **Infer Functionality of `CullRect`:** Based on the tests, I'd deduce the core functionalities of the `CullRect` class. It appears to represent a rectangular area used for culling (optimizing rendering by skipping drawing things outside this area). It has methods to:
    * Check for intersection with other rectangles (potentially transformed).
    * Represent an infinite area.
    * Move its position.
    * Apply transformations (affine and scroll-related).
    * Determine if it has changed significantly.
    * Interact with paint properties.

7. **Relate to Web Technologies (if applicable):** I would then consider how the functionality of `CullRect` relates to JavaScript, HTML, and CSS. Culling is a rendering optimization, and while developers don't directly manipulate `CullRect` objects, their actions in creating web pages *influence* how the rendering engine uses culling. For example:
    * **Scrolling:** The `ApplyScrollTranslation` tests clearly link `CullRect` to handling scrolling, which is a fundamental user interaction in web pages.
    * **Transformations:** CSS `transform` properties (translate, rotate, scale) directly impact the transformations applied to elements, and thus influence the culling rectangles used for those elements.
    * **Clipping:** The tests involving `CreateClip` relate to CSS `clip-path` or the older `clip` property, where parts of an element are hidden. Culling can be affected by these clipping regions.
    * **Layout and Overflow:**  The size and position of elements, managed by the layout engine based on HTML and CSS, determine the initial bounding rectangles that might be used for culling. Overflow properties (`overflow: hidden`, `scroll`, `auto`) create scroll containers, which are central to the `ApplyScrollTranslation` logic.

8. **Identify Logical Reasoning and Assumptions:** The tests involving `ApplyScrollTranslation` and `ApplyPaintProperties` often involve specific input states and expected output rectangles. I'd examine these to understand the logical transformations being applied. For instance, understanding how a scroll offset and container size affect the final cull rectangle. I'd also note assumptions made in the tests, such as the initial state of the `CullRect` or the properties of the transformation matrices.

9. **Recognize Potential User/Programming Errors:**  While the test file itself doesn't directly cause user errors, it *tests the behavior* of the `CullRect` class in various scenarios. Understanding these scenarios can help identify potential issues in the rendering engine's implementation. For example, if the `ChangedEnough` logic is flawed, it could lead to unnecessary repainting or, conversely, to skipped repainting when necessary. As a developer working on the rendering engine, misunderstanding how `ApplyPaintProperties` interacts with different property tree states could lead to incorrect culling.

10. **Summarize the Functionality:** Finally, I'd synthesize the information gathered into a concise summary of the file's purpose and the functionality of the `CullRect` class it tests. This involves highlighting the key capabilities and how they contribute to the rendering process.

By following these steps, I can systematically analyze the provided C++ test file and extract meaningful information about its function, its relationship to web technologies, its underlying logic, and potential error scenarios. This methodical approach ensures a comprehensive understanding of the code.
这是 chromium blink 引擎源代码文件 `cull_rect_test.cc` 的第一部分，主要功能是 **测试 `CullRect` 类的各项功能**。`CullRect` 类很可能用于表示一个用于剔除（culling）的矩形区域，这是渲染引擎中优化绘制性能的关键技术。

以下是对其功能的详细列举和说明：

**主要功能归纳:**

* **单元测试框架:** 使用 Google Test 框架 (`testing/gtest/include/gtest/gtest.h`) 来编写测试用例。
* **`CullRect` 类测试:**  针对 `CullRect` 类的各种方法进行功能验证，确保其行为符合预期。
* **几何运算测试:** 测试 `CullRect` 与其他矩形进行交集判断 (`Intersects`, `IntersectsTransformed`)。
* **变换测试:** 测试 `CullRect` 如何应用各种变换，包括平移 (`Move`, `ApplyTransform`) 和滚动平移 (`ApplyScrollTranslation`)。
* **属性应用测试:** 测试 `CullRect` 如何应用 Paint Properties，这涉及到渲染流程中属性的传递和应用 (`ApplyPaintProperties`)。
* **变化检测测试:** 测试 `CullRect` 判断自身是否发生足够变化的方法 (`ChangedEnough`)。
* **边界情况测试:**  包含对无限大矩形 (`Infinite`) 和空矩形的测试。

**与 JavaScript, HTML, CSS 的关系 (间接):**

`CullRect` 类是 Blink 渲染引擎内部的一部分，它本身不直接与 JavaScript, HTML, CSS 代码交互。但是，它的功能直接影响到网页的渲染性能和结果。

* **HTML 结构和元素布局:** HTML 定义了网页的结构，元素的尺寸和位置会影响 `CullRect` 的初始值。例如，一个 `<div>` 元素的几何尺寸会成为某个渲染对象的初始剔除矩形。
* **CSS 样式和视觉效果:** CSS 负责元素的样式，包括位置、变换、裁剪等。
    * **`transform` 属性:** CSS 的 `transform` 属性（例如 `translate`, `rotate`, `scale`）会直接影响 `ApplyTransform` 测试中 `CullRect` 的变换。
    * **滚动:** 当用户滚动网页时，`ApplyScrollTranslation` 测试模拟了滚动对 `CullRect` 的影响。CSS 的 `overflow` 属性决定了元素是否可以滚动。
    * **`clip` 或 `clip-path` 属性:** CSS 的裁剪属性会影响渲染对象的可见区域，进而可能影响 `CullRect` 的计算或应用。测试中涉及到 `CreateClip` 函数，模拟了裁剪区域。
* **JavaScript 动画和交互:** JavaScript 可以动态修改元素的样式和位置，这会导致渲染引擎重新计算布局和绘制。`CullRect` 的有效工作可以避免不必要的重绘，提高 JavaScript 动画和交互的性能。

**逻辑推理 (假设输入与输出):**

以下是一些测试用例中隐含的逻辑推理，以及假设的输入和输出：

* **`TEST_F(CullRectTest, IntersectsRect)`:**
    * **假设输入:** 一个 `CullRect` 对象表示矩形 (0, 0, 50, 50)，以及不同的测试矩形。
    * **逻辑推理:** 判断测试矩形是否与 `CullRect` 表示的矩形相交。
    * **预期输出:**  `EXPECT_TRUE` 或 `EXPECT_FALSE`，表示是否相交。例如，测试矩形 (0, 0, 1, 1) 与 (0, 0, 50, 50) 相交，所以 `EXPECT_TRUE`。测试矩形 (51, 51, 1, 1) 不相交，所以 `EXPECT_FALSE`。
* **`TEST_F(CullRectTest, ApplyTransform)`:**
    * **假设输入:** 一个 `CullRect` 对象表示矩形 (1, 1, 50, 50)，以及一个平移变换矩阵。
    * **逻辑推理:** 将变换矩阵应用到 `CullRect` 上，相当于将矩形向左上平移 1 个单位。
    * **预期输出:** `CullRect` 的矩形变为 (0, 0, 50, 50)。
* **`TEST_F(CullRectTest, ApplyScrollTranslationPartialScrollingContents1)`:**
    * **假设输入:** 一个 `CullRect` 对象表示矩形 (0, 0, 50, 100)，一个滚动平移状态，包含滚动偏移 (-5000)，内容区域 (20, 10, 40, 50)，和内容大小 (40, 8000)。
    * **逻辑推理:**  模拟一个部分滚动的场景。首先，将 `CullRect` 裁剪到内容区域，然后进行反向的滚动平移，并根据内容大小进行扩展。
    * **预期输出:** `CullRect` 的矩形变为 (20, 1010, 30, 7000)。  具体的计算涉及到裁剪、反向变换和扩展逻辑。
* **`TEST_F(CullRectTest, ChangedEnoughOnMovement)`:**
    * **假设输入:** 一个 `CullRect` 对象表示矩形 (100, 100, 100, 100)，以及一个偏移量。
    * **逻辑推理:** 判断矩形的移动距离是否超过了某个阈值，从而认为发生了“足够”的变化。
    * **预期输出:** `EXPECT_TRUE` 或 `EXPECT_FALSE`。例如，偏移 (500, 0) 和 (0, 500) 不足以导致变化，而偏移 (50, 0) 和 (-50, 50) 则被认为是足够的变化。

**用户或编程常见的使用错误 (针对 Blink 引擎开发者):**

虽然用户不会直接使用 `CullRect`，但 Blink 引擎的开发者在使用或修改相关代码时可能会犯以下错误：

* **错误的变换应用:**  在 `ApplyTransform` 或 `ApplyScrollTranslation` 中，如果变换矩阵计算错误，会导致 `CullRect` 的位置和大小计算错误，从而影响渲染剔除的效果，可能导致应该绘制的内容被剔除，或者不应该绘制的内容被绘制。
    * **示例:**  假设滚动偏移量计算错误，导致 `ApplyScrollTranslation` 后的 `CullRect` 位置偏差很大。
* **`ChangedEnough` 阈值设置不当:** 如果 `ChangedEnough` 的阈值设置得太高，可能会导致一些需要重绘的区域没有被标记为变化，导致画面更新不及时。反之，阈值太低可能导致不必要的重绘，降低性能。
    * **示例:**  一个元素轻微移动，但 `ChangedEnough` 始终返回 `true`，导致该元素总是被重绘。
* **忽略无限大 `CullRect` 的特殊性:**  在处理 `CullRect::Infinite()` 时，如果没有进行特殊处理，可能会导致一些假设矩形边界的计算出现错误。
    * **示例:**  在与无限大 `CullRect` 进行交集判断时，没有考虑到它会与任何有限矩形相交。
* **在 Paint Properties 应用中传递错误的 State:**  `ApplyPaintProperties` 方法依赖于正确的 PropertyTreeState。如果传递了错误的 source 或 destination state，可能导致 `CullRect` 应用了错误的变换或裁剪。
    * **示例:**  在处理嵌套的滚动容器时，错误地传递了父容器的 State，导致子容器的 `CullRect` 计算错误。

**总结:**

`cull_rect_test.cc` 的第一部分定义了一系列的单元测试，用于验证 `CullRect` 类的核心功能，包括几何运算、变换应用、属性处理和变化检测。这些测试确保了 `CullRect` 能够正确地表示和操作用于渲染剔除的矩形区域，这对于 Blink 引擎的渲染性能至关重要。虽然普通用户不直接接触 `CullRect`，但其正确性直接影响到网页的渲染效果和性能，与 JavaScript, HTML, CSS 的渲染结果息息相关。

### 提示词
```
这是目录为blink/renderer/platform/graphics/paint/cull_rect_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/graphics/paint/cull_rect.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/testing/paint_property_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/transforms/affine_transform.h"
#include "ui/gfx/geometry/rect_f.h"

namespace blink {

class CullRectTest : public testing::Test {
 protected:
  bool ApplyPaintProperties(
      CullRect& cull_rect,
      const PropertyTreeState& root,
      const PropertyTreeState& source,
      const PropertyTreeState& destination,
      const std::optional<CullRect>& old_cull_rect = std::nullopt) {
    return cull_rect.ApplyPaintProperties(root, source, destination,
                                          old_cull_rect, expansion_ratio_);
  }

  std::pair<bool, bool> ApplyScrollTranslation(
      CullRect& cull_rect,
      const TransformPaintPropertyNode& t) {
    return cull_rect.ApplyScrollTranslation(t, t, expansion_ratio_);
  }

  bool ChangedEnough(const gfx::Rect& old_rect,
                     const gfx::Rect& new_rect,
                     const std::optional<gfx::Rect>& bounds = std::nullopt,
                     const std::pair<bool, bool>& expanded = {true, true}) {
    return CullRect(new_rect).ChangedEnough(expanded, CullRect(old_rect),
                                            bounds, 1.f);
  }

  float expansion_ratio_ = 1.f;
};

TEST_F(CullRectTest, IntersectsRect) {
  CullRect cull_rect(gfx::Rect(0, 0, 50, 50));

  EXPECT_TRUE(cull_rect.Intersects(gfx::Rect(0, 0, 1, 1)));
  EXPECT_FALSE(cull_rect.Intersects(gfx::Rect(51, 51, 1, 1)));
  EXPECT_FALSE(cull_rect.Intersects(gfx::Rect(1, 1, 1, 0)));

  EXPECT_TRUE(CullRect::Infinite().Intersects(gfx::Rect(0, 0, 1, 1)));
  EXPECT_FALSE(CullRect::Infinite().Intersects(gfx::Rect(1, 1, 1, 0)));
  EXPECT_FALSE(CullRect(gfx::Rect()).Intersects(gfx::Rect()));
}

TEST_F(CullRectTest, IntersectsTransformed) {
  CullRect cull_rect(gfx::Rect(0, 0, 50, 50));
  AffineTransform transform;
  transform.Translate(-2, -2);

  EXPECT_TRUE(
      cull_rect.IntersectsTransformed(transform, gfx::RectF(51, 51, 1, 1)));
  EXPECT_FALSE(cull_rect.Intersects(gfx::Rect(52, 52, 1, 1)));

  EXPECT_TRUE(CullRect::Infinite().IntersectsTransformed(
      transform, gfx::RectF(51, 51, 1, 1)));
  EXPECT_FALSE(CullRect::Infinite().IntersectsTransformed(
      transform, gfx::RectF(1, 1, 1, 0)));
}

TEST_F(CullRectTest, Infinite) {
  EXPECT_TRUE(CullRect::Infinite().IsInfinite());
  EXPECT_TRUE(CullRect(InfiniteIntRect()).IsInfinite());
  EXPECT_FALSE(CullRect(gfx::Rect(0, 0, 100, 100)).IsInfinite());
}

TEST_F(CullRectTest, Move) {
  CullRect cull_rect(gfx::Rect(0, 0, 50, 50));
  cull_rect.Move(gfx::Vector2d());
  EXPECT_EQ(gfx::Rect(0, 0, 50, 50), cull_rect.Rect());
  cull_rect.Move(gfx::Vector2d(10, 20));
  EXPECT_EQ(gfx::Rect(10, 20, 50, 50), cull_rect.Rect());
}

TEST_F(CullRectTest, MoveInfinite) {
  CullRect cull_rect = CullRect::Infinite();
  cull_rect.Move(gfx::Vector2d());
  EXPECT_TRUE(cull_rect.IsInfinite());
  cull_rect.Move(gfx::Vector2d(10, 20));
  EXPECT_TRUE(cull_rect.IsInfinite());
}

TEST_F(CullRectTest, ApplyTransform) {
  CullRect cull_rect(gfx::Rect(1, 1, 50, 50));
  auto* transform = CreateTransform(t0(), MakeTranslationMatrix(1, 1));
  cull_rect.ApplyTransform(*transform);

  EXPECT_EQ(gfx::Rect(0, 0, 50, 50), cull_rect.Rect());
}

TEST_F(CullRectTest, ApplyTransformInfinite) {
  CullRect cull_rect = CullRect::Infinite();
  auto* transform = CreateTransform(t0(), MakeTranslationMatrix(1, 1));
  cull_rect.ApplyTransform(*transform);
  EXPECT_TRUE(cull_rect.IsInfinite());
}

TEST_F(CullRectTest, ApplyScrollTranslationPartialScrollingContents1) {
  auto state = CreateCompositedScrollTranslationState(
      PropertyTreeState::Root(), 0, -5000, gfx::Rect(20, 10, 40, 50),
      gfx::Size(40, 8000));
  auto& scroll_translation = state.Transform();

  CullRect cull_rect(gfx::Rect(0, 0, 50, 100));

  // Clipped: (20, 10, 30, 50)
  // Inverse transformed: (20, 5010, 30, 50)
  // Expanded: (0, 1010, 30/40, 8050)
  // Then clipped by the contents rect.
  EXPECT_EQ(std::make_pair(false, true),
            ApplyScrollTranslation(cull_rect, scroll_translation));
  EXPECT_EQ(gfx::Rect(20, 1010, 30, 7000), cull_rect.Rect());

  cull_rect = CullRect::Infinite();
  // This result differs from the above result in width (30 vs 40)
  // because it's not clipped by the infinite input cull rect.
  EXPECT_EQ(std::make_pair(false, true),
            ApplyScrollTranslation(cull_rect, scroll_translation));
  EXPECT_EQ(gfx::Rect(20, 1010, 40, 7000), cull_rect.Rect());

  // This cull rect is fully contained by the container rect.
  cull_rect = CullRect(gfx::Rect(30, 10, 20, 30));
  EXPECT_EQ(std::make_pair(false, true),
            ApplyScrollTranslation(cull_rect, scroll_translation));
  // No expansion in the non-scrollable direction.
  EXPECT_EQ(gfx::Rect(30, 1010, 20, 7000), cull_rect.Rect());
}

TEST_F(CullRectTest, ApplyScrollTranslationPartialScrollingContents2) {
  auto state = CreateCompositedScrollTranslationState(
      PropertyTreeState::Root(), -3000, -5000, gfx::Rect(20, 10, 40, 50),
      gfx::Size(8000, 8000));
  auto& scroll_translation = state.Transform();

  CullRect cull_rect(gfx::Rect(0, 0, 50, 100));
  // Similar to ApplyScrollTranslationPartialScrollingContents1, but expands
  // cull rect along both axes.
  EXPECT_EQ(std::make_pair(true, true),
            ApplyScrollTranslation(cull_rect, scroll_translation));
  EXPECT_EQ(gfx::Rect(1020, 3010, 4030, 4050), cull_rect.Rect());
  cull_rect = CullRect::Infinite();
  EXPECT_EQ(std::make_pair(true, true),
            ApplyScrollTranslation(cull_rect, scroll_translation));
  EXPECT_EQ(gfx::Rect(1020, 3010, 4040, 4050), cull_rect.Rect());
}

TEST_F(CullRectTest,
       ApplyScrollTranslationPartialScrollingContentsExpansionRatio) {
  expansion_ratio_ = 3;
  auto state = CreateCompositedScrollTranslationState(
      PropertyTreeState::Root(), -9000, -15000, gfx::Rect(20, 10, 40, 50),
      gfx::Size(24000, 24000));
  auto& scroll_translation = state.Transform();

  CullRect cull_rect(gfx::Rect(0, 0, 50, 100));
  // Similar to ApplyScrollTranslationPartialScrollingContents1, but expands
  // cull rect along both axes.
  EXPECT_EQ(std::make_pair(true, true),
            ApplyScrollTranslation(cull_rect, scroll_translation));
  EXPECT_EQ(gfx::Rect(3020, 9010, 12030, 12050), cull_rect.Rect());
  cull_rect = CullRect::Infinite();
  EXPECT_EQ(std::make_pair(true, true),
            ApplyScrollTranslation(cull_rect, scroll_translation));
  EXPECT_EQ(gfx::Rect(3020, 9010, 12040, 12050), cull_rect.Rect());
}

TEST_F(CullRectTest,
       ApplyNonCompositedScrollTranslationPartialScrollingContents1) {
  auto state = CreateScrollTranslationState(PropertyTreeState::Root(), 0, -5000,
                                            gfx::Rect(20, 10, 40, 50),
                                            gfx::Size(40, 8000));
  auto& scroll_translation = state.Transform();

  CullRect cull_rect(gfx::Rect(0, 0, 50, 100));
  // Same as ApplyScrollTranslationPartialScrollingContents1.
  EXPECT_EQ(std::make_pair(false, true),
            ApplyScrollTranslation(cull_rect, scroll_translation));
  EXPECT_EQ(gfx::Rect(20, 1010, 30, 7000), cull_rect.Rect());

  cull_rect = CullRect::Infinite();
  EXPECT_EQ(std::make_pair(false, true),
            ApplyScrollTranslation(cull_rect, scroll_translation));
  EXPECT_EQ(gfx::Rect(20, 1010, 40, 7000), cull_rect.Rect());
}

TEST_F(CullRectTest,
       ApplyNonCompositedScrollTranslationPartialScrollingContents2) {
  auto state = CreateScrollTranslationState(PropertyTreeState::Root(), -3000,
                                            -5000, gfx::Rect(20, 10, 40, 50),
                                            gfx::Size(8000, 8000));
  auto& scroll_translation = state.Transform();

  CullRect cull_rect(gfx::Rect(0, 0, 50, 100));
  // Same as ApplyScrollTranslationPartialScrollingContents2.
  EXPECT_EQ(std::make_pair(true, true),
            ApplyScrollTranslation(cull_rect, scroll_translation));
  EXPECT_EQ(gfx::Rect(1020, 3010, 4030, 4050), cull_rect.Rect());
  cull_rect = CullRect::Infinite();
  EXPECT_EQ(std::make_pair(true, true),
            ApplyScrollTranslation(cull_rect, scroll_translation));
  EXPECT_EQ(gfx::Rect(1020, 3010, 4040, 4050), cull_rect.Rect());
}

TEST_F(CullRectTest,
       ApplyScrollTranslationPartialScrollingContentsWithoutExpansion) {
  expansion_ratio_ = 0;
  auto state = CreateCompositedScrollTranslationState(
      PropertyTreeState::Root(), -3000, -5000, gfx::Rect(20, 10, 40, 50),
      gfx::Size(8000, 8000));
  auto& scroll_translation = state.Transform();

  CullRect cull_rect(gfx::Rect(0, 0, 50, 100));
  EXPECT_EQ(std::make_pair(false, false),
            ApplyScrollTranslation(cull_rect, scroll_translation));

  // Clipped: (20, 10, 30, 50)
  // Inverse transformed: (3020, 5010, 30, 50)
  EXPECT_EQ(gfx::Rect(3020, 5010, 30, 50), cull_rect.Rect());

  cull_rect = CullRect::Infinite();
  EXPECT_EQ(std::make_pair(false, false),
            ApplyScrollTranslation(cull_rect, scroll_translation));
  // This result differs from the above result in width (40 vs 30)
  // because it's not clipped by the infinite input cull rect.
  EXPECT_EQ(gfx::Rect(3020, 5010, 40, 50), cull_rect.Rect());
}

TEST_F(CullRectTest, ApplyScrollTranslationNoIntersectionWithContainerRect) {
  auto state = CreateCompositedScrollTranslationState(
      PropertyTreeState::Root(), -10, -15, gfx::Rect(200, 100, 40, 50),
      gfx::Size(2000, 2000));
  auto& scroll_translation = state.Transform();

  CullRect cull_rect(gfx::Rect(0, 0, 50, 100));
  EXPECT_EQ(std::make_pair(false, false),
            ApplyScrollTranslation(cull_rect, scroll_translation));
  EXPECT_TRUE(cull_rect.Rect().IsEmpty());
}

TEST_F(CullRectTest,
       ApplyNonCompositedScrollTranslationNoIntersectionWithContainerRect) {
  auto state = CreateCompositedScrollTranslationState(
      PropertyTreeState::Root(), -10, -15, gfx::Rect(200, 100, 40, 50),
      gfx::Size(2000, 2000));
  auto& scroll_translation = state.Transform();

  CullRect cull_rect(gfx::Rect(0, 0, 50, 100));
  EXPECT_EQ(std::make_pair(false, false),
            ApplyScrollTranslation(cull_rect, scroll_translation));
  EXPECT_TRUE(cull_rect.Rect().IsEmpty());
}

TEST_F(CullRectTest, ApplyScrollTranslationWholeScrollingContents) {
  auto state = CreateCompositedScrollTranslationState(
      PropertyTreeState::Root(), -10, -15, gfx::Rect(20, 10, 40, 50),
      gfx::Size(2000, 2000));
  auto& scroll_translation = state.Transform();

  CullRect cull_rect(gfx::Rect(0, 0, 50, 100));
  EXPECT_EQ(std::make_pair(true, true),
            ApplyScrollTranslation(cull_rect, scroll_translation));

  // Clipped: (20, 10, 30, 50)
  // Inverse transformed: (30, 25, 30, 50)
  // Expanded: (-3970, -3975, 8030, 8050)
  // Then clipped by the contents rect.
  EXPECT_EQ(gfx::Rect(20, 10, 2000, 2000), cull_rect.Rect());

  cull_rect = CullRect::Infinite();
  EXPECT_EQ(std::make_pair(true, true),
            ApplyScrollTranslation(cull_rect, scroll_translation));
  EXPECT_EQ(gfx::Rect(20, 10, 2000, 2000), cull_rect.Rect());
}

TEST_F(CullRectTest,
       ApplyNonCompositedScrollTranslationWholeScrollingContents) {
  auto state = CreateScrollTranslationState(PropertyTreeState::Root(), -10, -15,
                                            gfx::Rect(20, 10, 40, 50),
                                            gfx::Size(2000, 2000));
  auto& scroll_translation = state.Transform();

  CullRect cull_rect(gfx::Rect(0, 0, 50, 100));
  // Same as ApplyScrollTranslationWholeScrollingContents.
  EXPECT_EQ(std::make_pair(true, true),
            ApplyScrollTranslation(cull_rect, scroll_translation));
  EXPECT_EQ(gfx::Rect(20, 10, 2000, 2000), cull_rect.Rect());
  cull_rect = CullRect::Infinite();
  EXPECT_EQ(std::make_pair(true, true),
            ApplyScrollTranslation(cull_rect, scroll_translation));
  EXPECT_EQ(gfx::Rect(20, 10, 2000, 2000), cull_rect.Rect());
}

TEST_F(CullRectTest,
       ApplyScrollTranslationWholeScrollingContentsWithoutExpansion) {
  expansion_ratio_ = 0;
  auto state = CreateCompositedScrollTranslationState(
      PropertyTreeState::Root(), -10, -15, gfx::Rect(20, 10, 40, 50),
      gfx::Size(2000, 2000));
  auto& scroll_translation = state.Transform();

  CullRect cull_rect(gfx::Rect(0, 0, 50, 100));
  EXPECT_EQ(std::make_pair(false, false),
            ApplyScrollTranslation(cull_rect, scroll_translation));

  // Clipped: (20, 10, 30, 50)
  // Inverse transformed: (30, 25, 30, 50)
  EXPECT_EQ(gfx::Rect(30, 25, 30, 50), cull_rect.Rect());

  cull_rect = CullRect::Infinite();
  EXPECT_EQ(std::make_pair(false, false),
            ApplyScrollTranslation(cull_rect, scroll_translation));
  // This result differs from the above result in height (40 vs 30)
  // because it's not clipped by the infinite input cull rect.
  EXPECT_EQ(gfx::Rect(30, 25, 40, 50), cull_rect.Rect());
}

TEST_F(CullRectTest, ChangedEnoughEmpty) {
  EXPECT_FALSE(ChangedEnough(gfx::Rect(), gfx::Rect()));
  EXPECT_FALSE(ChangedEnough(gfx::Rect(1, 1, 0, 0), gfx::Rect(2, 2, 0, 0)));
  EXPECT_TRUE(ChangedEnough(gfx::Rect(), gfx::Rect(0, 0, 1, 1)));
  EXPECT_FALSE(ChangedEnough(gfx::Rect(0, 0, 1, 1), gfx::Rect()));
}

TEST_F(CullRectTest, ChangedNotEnough) {
  gfx::Rect old_rect(100, 100, 100, 100);
  EXPECT_FALSE(ChangedEnough(old_rect, old_rect));
  EXPECT_FALSE(ChangedEnough(old_rect, gfx::Rect(100, 100, 90, 90)));
  EXPECT_FALSE(ChangedEnough(old_rect, gfx::Rect(100, 100, 100, 100)));
  EXPECT_FALSE(ChangedEnough(old_rect, gfx::Rect(1, 1, 200, 200)));
}

TEST_F(CullRectTest, ChangedEnoughOnMovement) {
  gfx::Rect old_rect(100, 100, 100, 100);
  gfx::Rect new_rect(old_rect);
  new_rect.Offset(500, 0);
  EXPECT_FALSE(ChangedEnough(old_rect, new_rect));
  new_rect.Offset(0, 500);
  EXPECT_FALSE(ChangedEnough(old_rect, new_rect));
  new_rect.Offset(50, 0);
  EXPECT_TRUE(ChangedEnough(old_rect, new_rect));
  new_rect.Offset(-50, 50);
  EXPECT_TRUE(ChangedEnough(old_rect, new_rect));
}

TEST_F(CullRectTest, ChangedEnoughNewRectTouchingEdge) {
  gfx::Rect bounds(0, 0, 500, 500);
  gfx::Rect old_rect(100, 100, 100, 100);
  // Top edge.
  EXPECT_FALSE(ChangedEnough(old_rect, gfx::Rect(100, 50, 100, 200), bounds));
  EXPECT_TRUE(ChangedEnough(old_rect, gfx::Rect(100, 0, 100, 200), bounds));
  // Left edge.
  EXPECT_FALSE(ChangedEnough(old_rect, gfx::Rect(50, 100, 200, 100), bounds));
  EXPECT_TRUE(ChangedEnough(old_rect, gfx::Rect(0, 100, 200, 100), bounds));
  // Bottom edge.
  EXPECT_FALSE(ChangedEnough(old_rect, gfx::Rect(100, 100, 100, 350), bounds));
  EXPECT_TRUE(ChangedEnough(old_rect, gfx::Rect(100, 100, 100, 400), bounds));
  // Right edge.
  EXPECT_FALSE(ChangedEnough(old_rect, gfx::Rect(100, 100, 350, 100), bounds));
  EXPECT_TRUE(ChangedEnough(old_rect, gfx::Rect(100, 100, 400, 100), bounds));

  // With offset.
  bounds.Offset(-100, 100);
  old_rect.Offset(-100, 100);
  // Top edge.
  EXPECT_FALSE(ChangedEnough(old_rect, gfx::Rect(0, 150, 100, 200), bounds));
  EXPECT_TRUE(ChangedEnough(old_rect, gfx::Rect(0, 100, 100, 200), bounds));
  // Left edge.
  EXPECT_FALSE(ChangedEnough(old_rect, gfx::Rect(-50, 200, 200, 100), bounds));
  EXPECT_TRUE(ChangedEnough(old_rect, gfx::Rect(-100, 200, 200, 100), bounds));
  // Bottom edge.
  EXPECT_FALSE(ChangedEnough(old_rect, gfx::Rect(0, 200, 100, 350), bounds));
  EXPECT_TRUE(ChangedEnough(old_rect, gfx::Rect(0, 200, 100, 400), bounds));
  // Right edge.
  EXPECT_FALSE(ChangedEnough(old_rect, gfx::Rect(0, 200, 350, 100), bounds));
  EXPECT_TRUE(ChangedEnough(old_rect, gfx::Rect(0, 200, 400, 100), bounds));
}

TEST_F(CullRectTest, ChangedEnoughOldRectTouchingEdge) {
  gfx::Rect bounds(0, 0, 500, 500);
  gfx::Rect new_rect(100, 100, 300, 300);
  // Top edge.
  EXPECT_FALSE(ChangedEnough(gfx::Rect(100, 0, 100, 100), new_rect, bounds));
  // Left edge.
  EXPECT_FALSE(ChangedEnough(gfx::Rect(0, 100, 100, 100), new_rect, bounds));
  // Bottom edge.
  EXPECT_FALSE(ChangedEnough(gfx::Rect(300, 400, 100, 100), new_rect, bounds));
  // Right edge.
  EXPECT_FALSE(ChangedEnough(gfx::Rect(400, 300, 100, 100), new_rect, bounds));

  // With offset.
  bounds.Offset(-100, 100);
  new_rect.Offset(-100, 100);
  // Top edge.
  EXPECT_FALSE(ChangedEnough(gfx::Rect(0, 100, 100, 100), new_rect, bounds));
  // Left edge.
  EXPECT_FALSE(ChangedEnough(gfx::Rect(-100, 0, 100, 100), new_rect, bounds));
  // Bottom edge.
  EXPECT_FALSE(ChangedEnough(gfx::Rect(200, 500, 100, 100), new_rect, bounds));
  // Right edge.
  EXPECT_FALSE(ChangedEnough(gfx::Rect(300, 400, 100, 100), new_rect, bounds));
}

TEST_F(CullRectTest, ChangedEnoughNotExpanded) {
  gfx::Rect old_rect(100, 100, 300, 300);
  // X is not expanded and unchanged, y isn't changed enough.
  EXPECT_FALSE(ChangedEnough(old_rect, gfx::Rect(100, 0, 300, 300),
                             std::nullopt, {false, true}));
  // X is not expanded and changed, y unchanged.
  EXPECT_TRUE(ChangedEnough(old_rect, gfx::Rect(0, 100, 300, 300), std::nullopt,
                            {false, true}));
  EXPECT_TRUE(ChangedEnough(old_rect, gfx::Rect(100, 100, 200, 300),
                            std::nullopt, {false, true}));

  // X isn't changed enough, y is not expanded and unchanged.
  EXPECT_FALSE(ChangedEnough(old_rect, gfx::Rect(0, 100, 300, 300),
                             std::nullopt, {true, false}));
  // X unchanged, Y is not expanded and changed.
  EXPECT_TRUE(ChangedEnough(old_rect, gfx::Rect(100, 0, 300, 300), std::nullopt,
                            {true, false}));
  EXPECT_TRUE(ChangedEnough(old_rect, gfx::Rect(100, 100, 300, 200),
                            std::nullopt, {true, false}));
}

TEST_F(CullRectTest, ApplyPaintPropertiesWithoutClipScroll) {
  auto* t1 = CreateTransform(t0(), MakeTranslationMatrix(1, 2));
  auto* t2 = CreateTransform(*t1, MakeTranslationMatrix(10, 20));
  PropertyTreeState root = PropertyTreeState::Root();
  PropertyTreeState state1(*t1, c0(), e0());
  PropertyTreeState state2(*t2, c0(), e0());

  CullRect cull_rect1(gfx::Rect(1, 1, 50, 50));
  EXPECT_FALSE(ApplyPaintProperties(cull_rect1, root, state1, state2));
  EXPECT_EQ(gfx::Rect(-9, -19, 50, 50), cull_rect1.Rect());

  CullRect cull_rect2(gfx::Rect(1, 1, 50, 50));
  EXPECT_FALSE(ApplyPaintProperties(cull_rect2, root, root, state2));
  EXPECT_EQ(gfx::Rect(-10, -21, 50, 50), cull_rect2.Rect());

  CullRect old_cull_rect = cull_rect2;
  old_cull_rect.Move(gfx::Vector2d(1, 1));
  CullRect cull_rect3(gfx::Rect(1, 1, 50, 50));
  // Should ignore old_cull_rect.
  EXPECT_FALSE(ApplyPaintProperties(cull_rect3, root, root, state2));
  EXPECT_EQ(cull_rect2, cull_rect3);

  CullRect infinite = CullRect::Infinite();
  EXPECT_FALSE(ApplyPaintProperties(infinite, root, root, state2));
  EXPECT_TRUE(infinite.IsInfinite());
}

TEST_F(CullRectTest, SingleScrollWholeCompsitedScrollingContents) {
  auto* t1 = CreateTransform(t0(), MakeTranslationMatrix(1, 2));
  PropertyTreeState state1(*t1, c0(), e0());
  auto scroll_translation_state = CreateCompositedScrollTranslationState(
      state1, -10, -15, gfx::Rect(20, 10, 40, 50), gfx::Size(2000, 2000));

  // Same as ApplyScrollTranslationWholeScrollingContents.
  CullRect cull_rect1(gfx::Rect(0, 0, 50, 100));
  EXPECT_TRUE(ApplyPaintProperties(cull_rect1, state1, state1,
                                   scroll_translation_state));
  EXPECT_EQ(gfx::Rect(20, 10, 2000, 2000), cull_rect1.Rect());

  CullRect old_cull_rect = cull_rect1;
  old_cull_rect.Move(gfx::Vector2d(1, 1));
  CullRect cull_rect2(gfx::Rect(0, 0, 50, 100));
  // Should ignore old_cull_rect.
  EXPECT_TRUE(ApplyPaintProperties(cull_rect2, state1, state1,
                                   scroll_translation_state, old_cull_rect));
  EXPECT_EQ(cull_rect1, cull_rect2);

  CullRect cull_rect3 = CullRect::Infinite();
  EXPECT_TRUE(ApplyPaintProperties(cull_rect3, state1, state1,
                                   scroll_translation_state));
  EXPECT_EQ(gfx::Rect(20, 10, 2000, 2000), cull_rect3.Rect());
}

TEST_F(CullRectTest, ApplyTransformsWithOrigin) {
  auto* t1 = CreateTransform(t0(), MakeTranslationMatrix(1, 2));
  auto* t2 =
      CreateTransform(*t1, MakeScaleMatrix(0.5), gfx::Point3F(50, 100, 0));
  PropertyTreeState root = PropertyTreeState::Root();
  PropertyTreeState state1(*t1, c0(), e0());
  PropertyTreeState state2(*t2, c0(), e0());
  CullRect cull_rect1(gfx::Rect(0, 0, 50, 200));
  EXPECT_FALSE(ApplyPaintProperties(cull_rect1, root, state1, state2));
  EXPECT_EQ(gfx::Rect(-50, -100, 100, 400), cull_rect1.Rect());
}

TEST_F(CullRectTest, SingleScrollPartialScrollingContents) {
  auto* t1 = Create2DTranslation(t0(), 1, 2);
  PropertyTreeState state1(*t1, c0(), e0());

  auto scroll_translation_state = CreateCompositedScrollTranslationState(
      state1, -3000, -5000, gfx::Rect(20, 10, 40, 50), gfx::Size(8000, 8000));

  // Same as ApplyScrollTranslationPartialScrollingContents.
  CullRect cull_rect1(gfx::Rect(0, 0, 50, 100));
  EXPECT_TRUE(ApplyPaintProperties(cull_rect1, state1, state1,
                                   scroll_translation_state));
  EXPECT_EQ(gfx::Rect(1020, 3010, 4030, 4050), cull_rect1.Rect());

  CullRect old_cull_rect(gfx::Rect(1000, 3100, 4000, 4000));
  CullRect cull_rect2(gfx::Rect(0, 0, 50, 100));
  // Use old_cull_rect if the new cull rect didn't change enough.
  EXPECT_TRUE(ApplyPaintProperties(cull_rect2, state1, state1,
                                   scroll_translation_state, old_cull_rect));
  EXPECT_EQ(old_cull_rect, cull_rect2);

  old_cull_rect.Move(gfx::Vector2d(1000, 1000));
  CullRect cull_rect3(gfx::Rect(0, 0, 50, 100));
  // Use the new cull rect if it changed enough.
  EXPECT_TRUE(ApplyPaintProperties(cull_rect3, state1, state1,
                                   scroll_translation_state, old_cull_rect));
  EXPECT_EQ(cull_rect1, cull_rect3);

  CullRect cull_rect4 = CullRect::Infinite();
  EXPECT_TRUE(ApplyPaintProperties(cull_rect4, state1, state1,
                                   scroll_translation_state));
  // This result differs from the first result in width (4030 vs 4040)
  // because it's not clipped by the infinite input cull rect.
  EXPECT_EQ(gfx::Rect(1020, 3010, 4040, 4050), cull_rect4.Rect());
}

TEST_F(CullRectTest, TransformUnderScrollTranslation) {
  auto* t1 = Create2DTranslation(t0(), 1, 2);
  PropertyTreeState state1(*t1, c0(), e0());
  auto scroll_translation_state = CreateCompositedScrollTranslationState(
      state1, -3000, -5000, gfx::Rect(20, 10, 40, 50), gfx::Size(8000, 8000));
  auto* t2 =
      Create2DTranslation(scroll_translation_state.Transform(), 2000, 3000);
  PropertyTreeState state2 = scroll_translation_state;
  state2.SetTransform(*t2);

  // Cases below are the same as those in SingleScrollPartialScrollingContents,
  // except that the offset is adjusted with |t2|.
  CullRect cull_rect1(gfx::Rect(0, 0, 50, 100));
  EXPECT_TRUE(ApplyPaintProperties(cull_rect1, state1, state1, state2));
  EXPECT_EQ(gfx::Rect(-980, 10, 4030, 4050), cull_rect1.Rect());

  CullRect old_cull_rect(gfx::Rect(-980, 10, 4000, 4000));
  CullRect cull_rect2(gfx::Rect(0, 0, 50, 100));
  // Use old_cull_rect if the new cull rect didn't change enough.
  EXPECT_TRUE(
      ApplyPaintProperties(cull_rect2, state1, state1, state2, old_cull_rect));
  EXPECT_EQ(old_cull_rect, cull_rect2);

  old_cull_rect.Move(gfx::Vector2d(1000, 1000));
  CullRect cull_rect3(gfx::Rect(0, 0, 50, 100));
  // Use the new cull rect if it changed enough.
  EXPECT_TRUE(
      ApplyPaintProperties(cull_rect3, state1, state1, state2, old_cull_rect));
  EXPECT_EQ(cull_rect1, cull_rect3);

  CullRect cull_rect4 = CullRect::Infinite();
  EXPECT_TRUE(ApplyPaintProperties(cull_rect4, state1, state1, state2));
  // This result differs from the first result in height (7050 vs 7060)
  // because it's not clipped by the infinite input cull rect.
  EXPECT_EQ(gfx::Rect(-980, 10, 4040, 4050), cull_rect4.Rect());
}

TEST_F(CullRectTest, TransformEscapingScroll) {
  PropertyTreeState root = PropertyTreeState::Root();
  auto* t1 = CreateTransform(t0(), MakeTranslationMatrix(1, 2));
  auto* c1 = CreateClip(c0(), t0(), FloatRoundedRect(111, 222, 333, 444));
  PropertyTreeState state1(*t1, *c1, e0());

  auto scroll_translation_state = CreateCompositedScrollTranslationState(
      state1, -3000, -5000, gfx::Rect(20, 10, 40, 50), gfx::Size(8000, 8000));

  auto* t2 = CreateTransform(scroll_translation_state.Transform(),
                             MakeTranslationMatrix(100, 200));
  PropertyTreeState state2(*t2, scroll_translation_state.Clip(), e0());

  CullRect cull_rect1(gfx::Rect(0, 0, 50, 100));
  // Ignore the current cull rect, and apply paint properties from root to
  // state1 on infinite cull rect instead.
  EXPECT_FALSE(ApplyPaintProperties(cull_rect1, root, state2, state1));
  EXPECT_EQ(gfx::Rect(110, 220, 333, 444), cull_rect1.Rect());

  CullRect old_cull_rect = cull_rect1;
  old_cull_rect.Move(gfx::Vector2d(1, 1));
  CullRect cull_rect2(gfx::Rect(0, 0, 50, 100));
  // Should ignore old_cull_rect.
  EXPECT_FALSE(
      ApplyPaintProperties(cull_rect2, root, state2, state1, old_cull_rect));
  EXPECT_EQ(cull_rect1, cull_rect2);

  CullRect cull_rect3 = CullRect::Infinite();
  EXPECT_FALSE(ApplyPaintProperties(cull_rect3, root, state2, state1));
  EXPECT_EQ(cull_rect1, cull_rect3);
}

TEST_F(CullRectTest, SmallScrollContentsAfterBigScrollContents) {
  auto* t1 = CreateTransform(t0(), MakeTranslationMatrix(1, 2));
  PropertyTreeState state1(*t1, c0(), e0());

  auto scroll_translation_state1 = CreateCompositedScrollTranslationState(
      state1, -10, -15, gfx::Rect(20, 10, 40, 50), gfx::Size(8000, 8000));

  auto* t2 = CreateTransform(scroll_translation_state1.Transform(),
                             MakeTranslationMatrix(1000, 1500));
  PropertyTreeState state2(*t2, scroll_translation_state1.Clip(), e0());

  auto scroll_translation_state2 = CreateCompositedScrollTranslationState(
      state2, -10, -15, gfx::Rect(30, 20, 100, 200), gfx::Size(200, 400));

  CullRect cull_rect1(gfx::Rect(0, 0, 50, 100));
  EXPECT_TRUE(ApplyPaintProperties(cull_rect1, state1, state1,
                                   scroll_translation_state2));
  EXPECT_EQ(gfx::Rect(30, 20, 200, 400), cull_rect1.Rect());

  CullRect old_cull_rect = cull_rect1;
  old_cull_rect.Move(gfx::Vector2d(1, 1));
  CullRect cull_rect2(gfx::Rect(0, 0, 50, 100));
  // Should ignore old_cull_rect.
  EXPECT_TRUE(ApplyPaintProperties(cull_rect2, state1, state1,
                                   scroll_translation_state2, old_cull_rect));
  EXPECT_EQ(cull_rect1, cull_rect2);
}

TEST_F(CullRectTest, BigScrollContentsAfterSmallScrollContents) {
  auto* t1 = CreateTransform(t0(), MakeTranslationMatrix(1, 2));
  PropertyTreeState state1(*t1, c0(), e0());

  auto scroll_translation_state1 = CreateCompositedScrollTranslationState(
      state1, -10, -15, gfx::Rect(30, 20, 100, 200), gfx::Size(200, 400));

  auto* t2 = CreateTransform(scroll_translation_state1.Transform(),
                             MakeTranslationMatrix(10, 20));
  PropertyTreeState state2(*t2, scroll_translation_state1.Clip(), e0());

  auto scroll_translation_state2 = CreateCompositedScrollTranslationState(
      state2, -3000, -5000, gfx::Rect(20, 10, 50, 100),
      gfx::Size(10000, 20000));

  CullRect cull_rect1(gfx::Rect(0, 0, 100, 200));
  EXPECT_TRUE(ApplyPaintProperties(cull_rect1, state1, state1,
                                   scroll_translation_state2));
  // After the first scroll: (-3960, -3965, 8070, 8180)
  // After t2: (-3980, -3975, 8070, 8180)
  // Clipped by the container rect of the second scroll: (20, 10, 50, 100)
  // After the second scroll offset: (3020, 5010, 50, 100)
  // Expanded: (1020, 3010, 4050, 4100)
  // Then clipped by the contents rect.
  EXPECT_EQ(gfx::Rect(1020, 3010, 4050, 4100), cull_rect1.Rect());

  CullRect old_cull_rect = cull_rect1;
  old_cull_rect.Move(gfx::Vector2d(0, 100));
  CullRect cull_rect2(gfx::Rect(0, 0, 100, 200));
  // Use old_cull_rect if the new cull rect didn't change enough.
  EXPECT_TRUE(ApplyPaintProperties(cull_rect2, state1, state1,
                                   scroll_translation_state2, old_cull_rect));
  EXPECT_EQ(old_cull_rect, cull_rect2);

  old_cull_rect.Move(gfx::Vector2d(1000, 1000));
  CullRect cull_rect3(gfx::Rect(0, 0, 100, 200));
  // Use the new cull rect if it changed enough.
  EXPECT_TRUE(ApplyPaintProperties(cull_rect3, state1, state1,
                                   scroll_translation_state2, old_cull_rect));
  EXPECT_EQ(cull_rect1, cull_rect3);
}

TEST_F(CullRectTest, NonCompositedTransformUnderClip) {
  PropertyTreeState root = PropertyTreeState::Root();
  auto* c1 = CreateClip(c0(), t0(), FloatRoundedRect(100, 200, 300, 400));
  auto* t1 = CreateTransform(t0(), MakeTranslationMatrix(10, 20));
  PropertyTreeState state1(*t1, *c1, e0());

  CullRect cull_rect1(gfx::Rect(0, 0, 300, 500));
  EXPECT_FALSE(ApplyPaintProperties(cull_rect1, root, root, state1));
  // Clip by c1, then transformed by t1.
  EXPECT_EQ(gfx::Rect(90, 180, 200, 300), cull_rect1.Rect());

  CullRect cull_rect2(gfx::Rect(0, 0, 300, 500));
  CullRect old_cull_rect(gfx::Rect(133, 244, 333, 444));
  // Should ignore old_cull_rect.
  EXPECT_FALSE(
      ApplyPaintProperties(cull_rect2, root, root, state1, old_cull_rect));
  EXPECT_EQ(cull_rect1, cull_rect2);

  CullRect cull_rect3 = CullRect::Infinite();
  EXPECT_FALSE(ApplyPaintProperties(cull_rect3, root, root, state1));
  EXPECT_EQ(gfx::Rect(90, 180, 300, 400), cull_rect3.Rect());

  CullRect cull_rect4;
  EXPECT_FALSE(ApplyPaintProperties(cull_rect4, root, root, state1));
  EXPECT_EQ(gfx::Rect(), cull_rect4.Rect());
}

TEST_F(CullRectTest, CompositedTranslationUnderClip) {
  PropertyTreeState root = PropertyTreeState::Root();
  auto* c1 = CreateClip(c0(), t0(), FloatRoundedRect(100, 200, 300, 400));
  auto transform = MakeTranslationMatrix(10, 20);
  transform.Scale3d(2, 4, 1);
  auto* t1 = CreateTransform(t0(), transform, gfx::Point3F(),
                             CompositingReason::kWillChangeTransform);
  PropertyTreeState state1(*t1, *c1, e0());

  CullRect cull_rect1(gfx::Rect(0, 0, 300, 500));
  EXPECT_TRUE(ApplyPaintProperties(cull_rect1, root, root, state1));
  // The result in NonCompositedTransformUnderClip expanded by 2000 (scaled by
  // minimum of 1/2 and 1/4), and clamped by minimum 2 * 512.
  EXPECT_EQ(gfx::Rect(-979, -979, 2148, 2123), cull_rect1.Rect());

  CullRect cull_rect2(gfx::Rect(0, 0, 300, 500));
  CullRect old_cull_rect = cull_rect1;
  old_cull_rect.Move(gfx::Vector2d(200, 200));
  // Use old_cull_rect if the new cull rect didn't change enough.
  EXPECT_TRUE(
      ApplyPaintProperties(cull_rect2, root, root, state1, old_cull_rect));
  EXPECT_EQ(old_cull_rect, cull_rect2);

  CullRect cull_rect3(gfx::Rect(0, 0, 300, 500));
  old_cull_rect.Move(gfx::Vector2d(1000, 1000));
  // Use the new cull rect if it changed enough.
  EXPECT_TRUE(
      ApplyPaintProperties(cull_rect3, root, root, state1, old_cull_rect));
  EXPECT_EQ(cull_rect1, cull_rect3);

  CullRect cull_rect4 = CullRect::Infinite();
  EXPECT_TRUE(ApplyPaintProperties(cull_rect4, root, root, state1));
  EXPECT_EQ(gfx::Rect(-979, -979, 2198, 2148), cull_rect4.Rect());

  CullRect cull_rect5;
  EXPECT_TRUE(ApplyPaintProperties(cull_rect4, root, root, state1));
  EXPECT_EQ(gfx::Rect(), cull_rect5.Rect());
}

TEST_F(CullRectTest, CompositedTransformUnderClipWithoutExpansion) {
  expansion_ratio_ = 0;
  PropertyTreeState root = PropertyTreeState::Root();
  auto* c1 = CreateClip(c0(), t0(), FloatRoundedRect(100, 200, 300, 400));
  auto* t1 =
      CreateTransform(t0(), MakeTranslationMatrix(10, 20), gfx::Point3F(),
                      CompositingReason::kWillChangeTransform);
  PropertyTreeState state1(*t1, *c1, e0());

  CullRect cull_rect1(gfx::Rect(0, 0, 300, 500));
  EXPECT_FALSE(ApplyPaintProperties(cull_rect1, root, root, state1));
  // Clip by c1, then transformed by t1.
  EXPECT_EQ(gfx::Rect(90, 180, 200, 300), cull_rect1.Rect());

  CullRect cull_rect2(gfx::Rect(0, 0, 300, 500));
  CullRect old_cull_rect(gfx::Rect(133, 244, 333, 444));
  // Should ignore old_cull_rect.
  EXPECT_FALSE(
      ApplyPaintProperties(cull_rect2, root, root, state1, old_cull_rect));
  EXPECT_EQ(cull_rect1, cull_rect2);

  CullRect cull_rect3 = CullRect::Infinite();
  EXPECT_FALSE(ApplyPaintProperties(cull_rect3, root, root, state1));
  EXPECT_EQ(gfx::Rect(90, 180, 300, 400), cull_rect3.Rect());
```