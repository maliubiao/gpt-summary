Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Functionality:** The file name `geometry_mapper_transform_cache_test.cc` immediately suggests that it's testing a component named `GeometryMapperTransformCache`. The `#include` directives confirm this and point to its header file. The presence of `testing/gtest/include/gtest/gtest.h` indicates the use of Google Test, a C++ testing framework.

2. **Understand the Test Structure:** The `GeometryMapperTransformCacheTest` class inherits from `testing::Test`. This is standard practice in Google Test for grouping related test cases. The `protected` members are helper functions to access and assert properties of the `GeometryMapperTransformCache`. The `TEST_F` macros define individual test cases within this fixture.

3. **Analyze Helper Functions (Protected Members):**  These functions are crucial for understanding how the tests interact with the `GeometryMapperTransformCache`. Let's go through some key ones:

    * `GetTransformCache`:  This implies the `TransformPaintPropertyNode` has a way to retrieve its associated cache.
    * `UpdateScreenTransform`:  Suggests the cache needs to be updated based on the transform node.
    * `ScreenTransformUpdated`:  Indicates a flag or mechanism to track whether the screen transform has been updated.
    * `GetScreenTransform`:  Retrieves the cached screen transform data.
    * `Check2dTranslationToRoot`:  This function seems to verify the behavior of 2D translations. The `EXPECT_EQ` calls are key – they're asserting that the cached values are as expected. It checks the `root_of_2d_translation`, `to_2d_translation_root`, and how transformations are applied to the "plane root".
    * `CheckRootAsPlaneRoot`, `CheckPlaneRootSameAs2dTranslationRoot`, `CheckPlaneRootDifferent2dTranslationRoot`: These functions deal with more complex scenarios involving different types of transformations (scale, rotation) and how the "plane root" is determined in these cases. The naming convention suggests different ways the plane root can relate to the 2D translation root.
    * `HasAnimationToPlaneRoot`, `HasAnimationToScreen`:  These suggest the cache might handle animations related to transformations.

4. **Examine Individual Test Cases (using `TEST_F`):**  Each `TEST_F` block focuses on a specific aspect of the `GeometryMapperTransformCache`'s behavior.

    * `All2dTranslations`:  Tests a simple chain of 2D translations. The expected output can be traced by summing the translation values.
    * `RootAsPlaneRootWithIntermediateScale`: Introduces a scaling transform in the middle of the chain. This likely tests how the cache handles combined transformations.
    * `IntermediatePlaneRootSameAs2dTranslationRoot`: Uses a rotation, which might cause the plane root to be different from the root.
    * `IntermediatePlaneRootDifferent2dTranslationRoot`: Combines rotation and scaling, creating a more complex scenario.
    * `TransformUpdate`:  This test is about dynamically updating the transformations in the property nodes and how the cache responds. It tests scenarios like changing a translation to a scale and then to a 3D transform. It also checks the lifecycle of the cached screen transform data.

5. **Infer Functionality of `GeometryMapperTransformCache`:** Based on the tests, we can infer the following responsibilities of `GeometryMapperTransformCache`:

    * **Caching Transformation Data:** It stores pre-computed transformation matrices and related information to avoid redundant calculations.
    * **Handling Different Transformation Types:** It needs to correctly handle 2D translations, scales, and 3D transforms (like rotations).
    * **Determining the "Plane Root":**  A key concept seems to be the "plane root," which likely represents a coordinate space used for certain types of transformations. The cache needs to determine this correctly.
    * **Calculating Transformations to Root and Screen:**  It computes transformations relative to the root of the property tree and the screen.
    * **Optimization:** The caching mechanism aims to optimize performance by storing frequently used transformation data.
    * **Invalidation:** It needs to handle invalidation of the cache when the underlying transform properties change.
    * **Animation Support (potentially):** The `HasAnimationToPlaneRoot` and `HasAnimationToScreen` functions hint at supporting animated transformations.

6. **Relate to Web Technologies (JavaScript, HTML, CSS):**

    * **CSS `transform` Property:**  The core functionality directly relates to the CSS `transform` property. The `GeometryMapperTransformCache` likely plays a role in how Blink renders elements with CSS transformations.
    * **JavaScript Animation API (e.g., `requestAnimationFrame`):** The potential animation support connects to how JavaScript animations manipulate CSS transformations. The cache would need to efficiently update and apply these animated transformations.
    * **HTML Structure (DOM Tree):** The "root" and parent-child relationships of `TransformPaintPropertyNode` mirror the structure of the HTML DOM tree. Transformations are often inherited down the tree.

7. **Consider User/Developer Errors:**

    * **Incorrect Transform Order in CSS:**  While the cache itself might not directly *cause* this, its correct functioning is essential for rendering the effects of CSS transform order. If a developer specifies an incorrect order (e.g., translate then rotate vs. rotate then translate), the cache ensures Blink applies the transformations as defined.
    * **Performance Issues with Complex Transformations:** If a web page has extremely complex and frequently changing transformations, the cache's efficiency becomes critical. Inefficient cache management or very frequent invalidations could lead to performance problems.
    * **Understanding Transformation Concepts:**  Developers need to understand how transformations work (translation, rotation, scale, matrix transformations) to use CSS `transform` effectively. The underlying cache implementation makes these concepts work correctly in the browser.

8. **Hypothetical Input/Output (for `Check2dTranslationToRoot`):**

    * **Input:** A `TransformPaintPropertyNode` representing a 2D translation by (3, 4).
    * **Expected Output:**
        * `cache.root_of_2d_translation()` should point to the root node (`t0`).
        * `cache.to_2d_translation_root()` should be `gfx::Vector2dF(3, 4)`.
        * `actual_to_plane_root` (after `ApplyToPlaneRoot`) should be a translation matrix by (3, 4).
        * `actual_from_plane_root` (after `ApplyFromPlaneRoot`) should be a translation matrix by (-3, -4).

By following these steps, we can dissect the C++ test file, understand its purpose, and connect it to the broader context of web development. The process involves code analysis, understanding the testing framework, and making logical inferences about the functionality being tested.
这个 C++ 文件 `geometry_mapper_transform_cache_test.cc` 是 Chromium Blink 引擎的一部分，专门用于测试 `GeometryMapperTransformCache` 类的功能。`GeometryMapperTransformCache` 的作用是缓存与图形绘制相关的变换信息，以优化渲染性能。

以下是该文件的功能详细列表：

**核心功能：测试 `GeometryMapperTransformCache` 的以下方面:**

1. **2D 平移变换的缓存 (Caching of 2D Translation Transforms):**
   - 测试当只有 2D 平移变换时，缓存是否正确记录了从当前节点到根节点的累积平移量。
   - 验证 `root_of_2d_translation()` 是否指向 2D 平移的根节点。
   - 验证 `to_2d_translation_root()` 是否存储了正确的平移向量。
   - 验证 `ApplyToPlaneRoot()` 和 `ApplyFromPlaneRoot()` 是否能正确应用和反向应用平移变换。

2. **包含缩放变换的场景 (Scenarios with Scale Transforms):**
   - 测试当变换链中包含缩放变换时，缓存如何确定 "平面根" (plane root)。在这种情况下，平面根通常是引入缩放变换的节点。
   - 验证 `plane_root()` 是否指向正确的平面根节点。
   - 验证 `to_plane_root()` 是否存储了从当前节点到平面根的变换矩阵。
   - 验证 `from_plane_root()` 是否存储了从平面根到当前节点的反向变换矩阵。
   - 验证 `ApplyToScreen()` 和 `ApplyProjectionFromScreen()` 在这种场景下的行为。

3. **包含 3D 变换（例如旋转）的场景 (Scenarios with 3D Transforms, e.g., Rotation):**
   - 测试当变换链中包含 3D 变换时，缓存如何处理。引入 3D 变换的节点通常会成为新的平面根。
   - 验证 `to_screen()` 是否存储了从当前节点到屏幕的变换矩阵。
   - 验证 `projection_from_screen()` 是否存储了从屏幕到当前节点的投影变换矩阵。
   - 区分平面根与 2D 平移根不同的情况。

4. **变换更新 (Transform Updates):**
   - 测试当变换属性节点的状态发生变化时，缓存是否能够正确地更新其存储的信息。
   - 测试当中间节点的变换类型改变时（例如，从平移变为缩放或 3D 变换），缓存如何更新。
   - 测试 `UpdateScreenTransform()` 方法的作用，以及它如何标记屏幕变换是否已更新。
   - 测试缓存的失效机制 (`ClearCache()`) 以及失效后重新计算缓存值的过程。

5. **屏幕变换的缓存 (Caching of Screen Transforms):**
   - 测试屏幕变换是否被缓存，以及何时更新。
   - 验证 `ScreenTransformUpdated()` 方法的正确性。
   - 验证 `GetScreenTransform()` 方法返回的屏幕变换指针的生命周期。

6. **动画相关的缓存 (Caching related to Animations):**
   - 虽然这个测试文件没有深入测试动画，但它包含了 `HasAnimationToPlaneRoot()` 和 `HasAnimationToScreen()` 这样的辅助函数，暗示了 `GeometryMapperTransformCache` 可能会处理与动画相关的变换。

**与 JavaScript, HTML, CSS 的关系:**

`GeometryMapperTransformCache` 的功能直接关系到浏览器如何渲染使用了 CSS `transform` 属性的 HTML 元素。

* **CSS `transform` 属性:**  当你在 CSS 中使用 `transform: translate(10px, 20px)`, `transform: rotate(45deg)`, `transform: scale(0.5)`, 或更复杂的变换时，Blink 引擎会使用 `GeometryMapperTransformCache` 来缓存这些变换信息。
    * **例子:** 如果一个 HTML `div` 元素应用了 `transform: translateX(50px); transform: translateY(100px);`，`GeometryMapperTransformCache` 会缓存这个总共的 2D 平移量。

* **JavaScript 操作 CSS 变换:** JavaScript 可以通过修改元素的 `style.transform` 属性来动态改变元素的变换。当 JavaScript 修改变换时，`GeometryMapperTransformCache` 需要更新其缓存。
    * **例子:**  一个 JavaScript 动画可能通过 `element.style.transform = 'translateX(' + x + 'px)';` 来改变元素的位置。`GeometryMapperTransformCache` 需要跟踪这些变化。

* **渲染优化:** 缓存变换信息的主要目的是为了优化渲染性能。当元素及其祖先的变换没有改变时，Blink 可以直接使用缓存的变换信息，而不需要重新计算，从而提高渲染效率。

**逻辑推理、假设输入与输出:**

以 `Check2dTranslationToRoot` 函数为例：

**假设输入:**

* `node`: 一个 `TransformPaintPropertyNode` 对象，代表一个应用了 2D 平移变换的元素。
* 假设 `node` 的变换是相对于其父节点平移了 `(x, y)`。

**逻辑推理:**

* 如果 `node` 的所有祖先也都是 2D 平移变换，那么从 `node` 到根节点的总平移量应该是所有祖先平移量的累加。
* `root_of_2d_translation()` 应该指向第一个不是 2D 平移变换的祖先节点（通常是根节点）。
* `to_2d_translation_root()` 应该存储从 `node` 到 `root_of_2d_translation()` 的累积平移向量。
* `ApplyToPlaneRoot()` 应该返回一个表示平移 `(x, y)` 的变换矩阵。
* `ApplyFromPlaneRoot()` 应该返回一个表示平移 `(-x, -y)` 的变换矩阵。

**预期输出 (以 `TEST_F(GeometryMapperTransformCacheTest, All2dTranslations)` 中的 `Check2dTranslationToRoot(*t3, 8, 10);` 为例):**

* 假设 `t3` 是通过一系列 2D 平移创建的：`t0` (0,0) -> `t1` (+1,+2) -> `t2` (+0,+0) -> `t3` (+7,+8)。
* `GetTransformCache(*t3).root_of_2d_translation()` 将指向 `t0`。
* `GetTransformCache(*t3).to_2d_translation_root()` 将等于 `gfx::Vector2dF(8, 10)` (1+0+7, 2+0+8)。
* `ApplyToPlaneRoot` 返回的变换矩阵将等同于平移 `(8, 10)`。
* `ApplyFromPlaneRoot` 返回的变换矩阵将等同于平移 `(-8, -10)`。

**用户或编程常见的使用错误:**

虽然 `GeometryMapperTransformCache` 是 Blink 引擎的内部实现，用户或开发者通常不会直接与之交互，但理解其背后的原理可以帮助避免一些与 CSS 变换相关的常见错误：

1. **过度使用复杂的变换:**  如果一个页面使用了大量复杂的 3D 变换或者频繁更新的变换，即使有缓存机制，也可能导致性能问题。开发者应该尽量优化变换的使用，避免不必要的复杂性。
    * **例子:**  在一个循环中不断修改一个元素的 `transform: matrix3d(...)` 属性，可能会导致频繁的缓存失效和重绘。

2. **不理解变换的层叠上下文 (Stacking Context):** CSS 的 `transform` 属性会创建新的层叠上下文。不理解层叠上下文可能会导致元素遮挡关系不符合预期。
    * **例子:**  一个设置了 `transform` 的元素可能会遮挡住 `z-index` 值更高的但没有设置 `transform` 的兄弟元素。

3. **变换原点 (Transform Origin) 的误用:**  `transform-origin` 属性定义了变换的中心点。如果变换原点设置不当，可能会导致旋转或缩放效果不符合预期。
    * **例子:**  对一个元素进行旋转，但 `transform-origin` 设置在元素的左上角，旋转的效果会与中心旋转不同。

4. **性能瓶颈分析:** 当遇到渲染性能问题时，开发者可以使用浏览器的开发者工具（例如 Chrome DevTools 的 Performance 面板）来分析瓶颈。理解 `GeometryMapperTransformCache` 的作用可以帮助开发者判断是否是变换相关的计算导致了性能问题。

总而言之，`geometry_mapper_transform_cache_test.cc` 文件通过一系列的单元测试，确保了 Blink 引擎的 `GeometryMapperTransformCache` 类能够正确、高效地缓存和管理图形变换信息，这对于流畅的网页渲染至关重要。虽然开发者不会直接操作这个类，但其正确性直接影响了使用 CSS `transform` 属性的网页的表现。

### 提示词
```
这是目录为blink/renderer/platform/graphics/paint/geometry_mapper_transform_cache_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/graphics/paint/geometry_mapper_transform_cache.h"

#include <utility>

#include "base/types/optional_util.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/graphics/paint/transform_paint_property_node.h"
#include "third_party/blink/renderer/platform/testing/paint_property_test_helpers.h"

namespace blink {

class GeometryMapperTransformCacheTest : public testing::Test {
 protected:
  static const GeometryMapperTransformCache& GetTransformCache(
      const TransformPaintPropertyNode& transform) {
    return transform.GetTransformCache();
  }

  static void UpdateScreenTransform(const TransformPaintPropertyNode& node) {
    node.GetTransformCache();  // Ensure the transform cache.
    node.UpdateScreenTransform();
  }

  static bool ScreenTransformUpdated(const TransformPaintPropertyNode& node) {
    return node.GetTransformCache().screen_transform_updated_;
  }

  static const GeometryMapperTransformCache::ScreenTransform*
  GetScreenTransform(const TransformPaintPropertyNode& node) {
    return base::OptionalToPtr(GetTransformCache(node).screen_transform_);
  }

  static void Check2dTranslationToRoot(const TransformPaintPropertyNode& node,
                                       double x,
                                       double y) {
    const auto& cache = GetTransformCache(node);
    EXPECT_EQ(&t0(), cache.root_of_2d_translation());
    EXPECT_EQ(gfx::Vector2dF(x, y), cache.to_2d_translation_root());

    EXPECT_TRUE(ScreenTransformUpdated(node));
    EXPECT_FALSE(GetScreenTransform(node));

    EXPECT_EQ(&t0(), cache.plane_root());
    gfx::Transform actual_to_plane_root;
    cache.ApplyToPlaneRoot(actual_to_plane_root);
    EXPECT_EQ(MakeTranslationMatrix(x, y), actual_to_plane_root);
    gfx::Transform actual_from_plane_root;
    cache.ApplyFromPlaneRoot(actual_from_plane_root);
    EXPECT_EQ(MakeTranslationMatrix(-x, -y), actual_from_plane_root);
  }

  static void CheckRootAsPlaneRoot(
      const TransformPaintPropertyNode& node,
      const TransformPaintPropertyNode& root_of_2d_translation,
      const gfx::Transform& to_plane_root,
      double translate_x,
      double translate_y) {
    const auto& cache = GetTransformCache(node);
    EXPECT_EQ(&root_of_2d_translation, cache.root_of_2d_translation());
    EXPECT_EQ(gfx::Vector2dF(translate_x, translate_y),
              cache.to_2d_translation_root());

    EXPECT_TRUE(ScreenTransformUpdated(node));
    EXPECT_FALSE(GetScreenTransform(node));

    EXPECT_EQ(&t0(), cache.plane_root());
    EXPECT_EQ(to_plane_root, cache.to_plane_root());
    EXPECT_EQ(to_plane_root.InverseOrIdentity(), cache.from_plane_root());

    gfx::Transform actual_to_screen;
    cache.ApplyToScreen(actual_to_screen);
    EXPECT_EQ(to_plane_root, actual_to_screen);
    gfx::Transform actual_projection_from_screen;
    cache.ApplyProjectionFromScreen(actual_projection_from_screen);
    EXPECT_EQ(to_plane_root.InverseOrIdentity(), actual_projection_from_screen);
  }

  static void CheckPlaneRootSameAs2dTranslationRoot(
      const TransformPaintPropertyNode& node,
      const gfx::Transform& to_screen,
      const TransformPaintPropertyNode& plane_root,
      double translate_x,
      double translate_y) {
    const auto& cache = GetTransformCache(node);
    EXPECT_EQ(&plane_root, cache.root_of_2d_translation());
    EXPECT_EQ(gfx::Vector2dF(translate_x, translate_y),
              cache.to_2d_translation_root());

    EXPECT_FALSE(ScreenTransformUpdated(node));
    UpdateScreenTransform(node);
    EXPECT_TRUE(ScreenTransformUpdated(node));
    EXPECT_TRUE(GetScreenTransform(node));

    EXPECT_EQ(&plane_root, cache.plane_root());
    EXPECT_EQ(to_screen, cache.to_screen());
    auto projection_from_screen = to_screen;
    projection_from_screen.Flatten();
    projection_from_screen = projection_from_screen.InverseOrIdentity();
    EXPECT_EQ(projection_from_screen, cache.projection_from_screen());
  }

  static void CheckPlaneRootDifferent2dTranslationRoot(
      const TransformPaintPropertyNode& node,
      const gfx::Transform& to_screen,
      const TransformPaintPropertyNode& plane_root,
      const gfx::Transform& to_plane_root,
      const TransformPaintPropertyNode& root_of_2d_translation,
      double translate_x,
      double translate_y) {
    const auto& cache = GetTransformCache(node);
    EXPECT_EQ(&root_of_2d_translation, cache.root_of_2d_translation());
    EXPECT_EQ(gfx::Vector2dF(translate_x, translate_y),
              cache.to_2d_translation_root());

    EXPECT_FALSE(ScreenTransformUpdated(node));
    UpdateScreenTransform(node);
    EXPECT_TRUE(ScreenTransformUpdated(node));
    EXPECT_TRUE(GetScreenTransform(node));

    EXPECT_EQ(&plane_root, cache.plane_root());
    EXPECT_EQ(to_plane_root, cache.to_plane_root());
    EXPECT_EQ(to_plane_root.InverseOrIdentity(), cache.from_plane_root());
    EXPECT_EQ(to_screen, cache.to_screen());
    auto projection_from_screen = to_screen;
    projection_from_screen.Flatten();
    projection_from_screen = projection_from_screen.InverseOrIdentity();
    EXPECT_EQ(projection_from_screen, cache.projection_from_screen());
  }

  static bool HasAnimationToPlaneRoot(const TransformPaintPropertyNode& node) {
    return node.GetTransformCache().has_animation_to_plane_root();
  }

  static bool HasAnimationToScreen(const TransformPaintPropertyNode& node) {
    return node.GetTransformCache().has_animation_to_screen();
  }
};

TEST_F(GeometryMapperTransformCacheTest, All2dTranslations) {
  auto* t1 = Create2DTranslation(t0(), 1, 2);
  auto* t2 = Create2DTranslation(*t1, 0, 0);
  auto* t3 = Create2DTranslation(*t2, 7, 8);

  Check2dTranslationToRoot(t0(), 0, 0);
  Check2dTranslationToRoot(*t1, 1, 2);
  Check2dTranslationToRoot(*t2, 1, 2);
  Check2dTranslationToRoot(*t3, 8, 10);
}

TEST_F(GeometryMapperTransformCacheTest, RootAsPlaneRootWithIntermediateScale) {
  auto* t1 = Create2DTranslation(t0(), 1, 2);
  auto* t2 = CreateTransform(*t1, MakeScaleMatrix(3));
  auto* t3 = Create2DTranslation(*t2, 7, 8);

  Check2dTranslationToRoot(t0(), 0, 0);
  Check2dTranslationToRoot(*t1, 1, 2);
  auto to_plane_root = MakeTranslationMatrix(1, 2);
  to_plane_root.Scale(3);
  CheckRootAsPlaneRoot(*t2, *t2, to_plane_root, 0, 0);
  to_plane_root.Translate(7, 8);
  CheckRootAsPlaneRoot(*t3, *t2, to_plane_root, 7, 8);
}

TEST_F(GeometryMapperTransformCacheTest,
       IntermediatePlaneRootSameAs2dTranslationRoot) {
  auto* t1 = Create2DTranslation(t0(), 1, 2);
  auto* t2 = CreateTransform(*t1, MakeRotationMatrix(0, 45, 0));
  auto* t3 = Create2DTranslation(*t2, 7, 8);

  Check2dTranslationToRoot(t0(), 0, 0);
  Check2dTranslationToRoot(*t1, 1, 2);
  auto to_screen = MakeTranslationMatrix(1, 2);
  to_screen.RotateAboutYAxis(45);
  CheckPlaneRootSameAs2dTranslationRoot(*t2, to_screen, *t2, 0, 0);
  to_screen.Translate(7, 8);
  CheckPlaneRootSameAs2dTranslationRoot(*t3, to_screen, *t2, 7, 8);
}

TEST_F(GeometryMapperTransformCacheTest,
       IntermediatePlaneRootDifferent2dTranslationRoot) {
  auto* t1 = Create2DTranslation(t0(), 1, 2);
  auto* t2 = CreateTransform(*t1, MakeRotationMatrix(0, 45, 0));
  auto* t3 = CreateTransform(*t2, MakeScaleMatrix(3));
  auto* t4 = Create2DTranslation(*t3, 7, 8);

  Check2dTranslationToRoot(t0(), 0, 0);
  Check2dTranslationToRoot(*t1, 1, 2);

  auto to_screen = MakeTranslationMatrix(1, 2);
  to_screen.RotateAboutYAxis(45);
  CheckPlaneRootSameAs2dTranslationRoot(*t2, to_screen, *t2, 0, 0);

  auto to_plane_root = MakeScaleMatrix(3);
  to_screen.Scale(3, 3);
  CheckPlaneRootDifferent2dTranslationRoot(*t3, to_screen, *t2, to_plane_root,
                                           *t3, 0, 0);

  to_plane_root.Translate(7, 8);
  to_screen.Translate(7, 8);
  CheckPlaneRootDifferent2dTranslationRoot(*t4, to_screen, *t2, to_plane_root,
                                           *t3, 7, 8);
}

TEST_F(GeometryMapperTransformCacheTest, TransformUpdate) {
  auto* t1 = Create2DTranslation(t0(), 1, 2);
  auto* t2 = Create2DTranslation(*t1, 0, 0);
  auto* t3 = Create2DTranslation(*t2, 7, 8);

  Check2dTranslationToRoot(t0(), 0, 0);
  Check2dTranslationToRoot(*t1, 1, 2);
  Check2dTranslationToRoot(*t2, 1, 2);
  Check2dTranslationToRoot(*t3, 8, 10);

  // Change t2 to a scale.
  GeometryMapperTransformCache::ClearCache();
  t2->Update(*t1, TransformPaintPropertyNode::State{{MakeScaleMatrix(3)}});
  Check2dTranslationToRoot(t0(), 0, 0);
  Check2dTranslationToRoot(*t1, 1, 2);
  auto to_plane_root = MakeTranslationMatrix(1, 2);
  to_plane_root.Scale(3);
  CheckRootAsPlaneRoot(*t2, *t2, to_plane_root, 0, 0);
  to_plane_root.Translate(7, 8);
  CheckRootAsPlaneRoot(*t3, *t2, to_plane_root, 7, 8);

  // Change t2 to a 3d transform so that it becomes a plane root.
  GeometryMapperTransformCache::ClearCache();
  t2->Update(*t1,
             TransformPaintPropertyNode::State{{MakeRotationMatrix(0, 45, 0)}});
  Check2dTranslationToRoot(t0(), 0, 0);
  Check2dTranslationToRoot(*t1, 1, 2);

  auto t2_to_screen = MakeTranslationMatrix(1, 2);
  t2_to_screen.RotateAboutYAxis(45);
  CheckPlaneRootSameAs2dTranslationRoot(*t2, t2_to_screen, *t2, 0, 0);
  auto t3_to_screen = t2_to_screen;
  t3_to_screen.Translate(7, 8);
  CheckPlaneRootSameAs2dTranslationRoot(*t3, t3_to_screen, *t2, 7, 8);

  auto* t2_screen_transform = GetScreenTransform(*t2);
  ASSERT_TRUE(t2_screen_transform);
  auto* t3_screen_transform = GetScreenTransform(*t3);
  ASSERT_TRUE(t3_screen_transform);

  // UpdateScreenTransform should not reallocate screen_transform_.
  UpdateScreenTransform(*t2);
  EXPECT_TRUE(ScreenTransformUpdated(*t2));
  UpdateScreenTransform(*t3);
  EXPECT_TRUE(ScreenTransformUpdated(*t3));
  EXPECT_EQ(t2_screen_transform, GetScreenTransform(*t2));
  EXPECT_EQ(t3_screen_transform, GetScreenTransform(*t3));

  // Invalidating cache should invalidate screen_transform_ but not free it.
  GeometryMapperTransformCache::ClearCache();
  t3->Update(
      *t2, TransformPaintPropertyNode::State{{MakeTranslationMatrix(28, 27)}});
  EXPECT_FALSE(ScreenTransformUpdated(*t2));
  EXPECT_FALSE(ScreenTransformUpdated(*t3));
  EXPECT_EQ(t2_screen_transform, GetScreenTransform(*t2));
  EXPECT_EQ(t3_screen_transform, GetScreenTransform(*t3));

  // Update screen transforms (by CheckPlaneRootSameAs2dTranslationRoot()).
  // Screen transforms should be valid and have expected values.
  CheckPlaneRootSameAs2dTranslationRoot(*t2, t2_to_screen, *t2, 0, 0);
  t3_to_screen = t2_to_screen;
  t3_to_screen.Translate(28, 27);
  CheckPlaneRootSameAs2dTranslationRoot(*t3, t3_to_screen, *t2, 28, 27);
  // The pointers should be also the same as before.
  EXPECT_EQ(t2_screen_transform, GetScreenTransform(*t2));
  EXPECT_EQ(t3_screen_transform, GetScreenTransform(*t3));

  // Change t2 back to a 2d translation.
  GeometryMapperTransformCache::ClearCache();
  t2->Update(
      *t1, TransformPaintPropertyNode::State{{MakeTranslationMatrix(11, 12)}});
  Check2dTranslationToRoot(t0(), 0, 0);
  Check2dTranslationToRoot(*t1, 1, 2);
  Check2dTranslationToRoot(*t2, 1 + 11, 2 + 12);
  Check2dTranslationToRoot(*t3, 1 + 11 + 28, 2 + 12 + 27);
}

}  // namespace blink
```