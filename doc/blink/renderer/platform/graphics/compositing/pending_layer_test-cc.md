Response:
The user is asking for an analysis of the provided C++ code file `pending_layer_test.cc`. I need to identify the functionalities tested in this file and determine if they relate to JavaScript, HTML, or CSS. If there are logical deductions, I should outline the input and output. Finally, I need to point out potential usage errors for developers.

**Plan:**

1. **Identify the Core Functionality:** The file name and the included headers suggest it's testing the `PendingLayer` class, specifically its merging behavior.
2. **Analyze Test Cases:** Go through each `TEST` block to understand what specific aspects of `PendingLayer` are being tested. Focus on the `Merge` function.
3. **Determine Relationships with Web Technologies:**  Consider how compositing and layers relate to HTML elements, CSS styling (especially properties that trigger compositing), and JavaScript's ability to manipulate the DOM and styles.
4. **Extract Logical Inferences:**  Look for test cases that demonstrate how the `Merge` function handles different scenarios (e.g., different bounds, transforms, opaqueness, text rendering hints). Identify the assumptions and expected outcomes.
5. **Identify Potential Usage Errors:**  Think about how a developer might misuse the `PendingLayer` class or its `Merge` function based on the tested scenarios. For example, incorrect assumptions about merging behavior could lead to unexpected rendering.
这个文件 `pending_layer_test.cc` 是 Chromium Blink 引擎中用于测试 `PendingLayer` 类功能的单元测试文件。 `PendingLayer`  类在渲染过程中用于管理待处理的渲染层信息，特别是在合成（compositing）过程中。

以下是该文件测试的主要功能：

**1. 合并 (Merge) 功能:**

*   **功能描述:** 该文件主要测试 `PendingLayer::Merge` 函数的行为。这个函数负责将一个 `PendingLayer` 对象（guest）合并到另一个 `PendingLayer` 对象（home）中。合并的过程中会更新 home 层的边界、包含的渲染块（PaintChunk）、不透明区域等信息。
*   **与 JavaScript, HTML, CSS 的关系:**
    *   **HTML:**  HTML 结构定义了页面上的元素，而每个元素可能对应一个或多个渲染层。`PendingLayer` 用于管理这些层的渲染信息。当 HTML 结构发生变化，例如添加或删除元素，可能会触发新的渲染层的创建和合并。
    *   **CSS:** CSS 样式会影响元素的渲染方式，并可能触发层的合成。例如，使用 `transform`, `opacity`, `filter` 等 CSS 属性可能会导致元素被提升为独立的合成层。 `PendingLayer` 负责管理这些合成层的相关信息。`Merge` 操作可能会发生在因为 CSS 样式的改变而需要更新合成层结构时。
    *   **JavaScript:** JavaScript 可以动态地修改 HTML 结构和 CSS 样式。当 JavaScript 引起这些变化时，底层的渲染引擎会更新渲染层的信息，这可能涉及到 `PendingLayer` 对象的创建和合并。例如，通过 JavaScript 改变一个元素的 `transform` 属性，可能会触发该元素所在层的合并操作。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入:** 两个 `PendingLayer` 对象，分别代表页面上的两个渲染区域。
    *   **输出:** 如果 `Merge` 操作成功，home `PendingLayer` 对象将包含两个原始层的信息，其边界会扩展到包含两个原始层，包含的渲染块也会增加。如果合并失败（例如，两个层距离太远，被认为是稀疏的），home `PendingLayer` 对象保持不变。
    *   **示例 (基于测试用例 `Merge`):**
        *   初始 `pending_layer` 基于第一个渲染块，其边界是 (0, 0, 30, 40)。
        *   合并第二个渲染块（边界 (10, 20, 30, 40)）后，`pending_layer` 的边界更新为 (0, 0, 40, 60)，包含了两个渲染块。
        *   继续合并第三个渲染块（边界 (-5, -25, 20, 20)）后，`pending_layer` 的边界更新为 (-5, -25, 45, 85)，包含了所有三个渲染块。

**2. 处理变换 (Transform) 的合并:**

*   **功能描述:** 测试在合并过程中，当待合并的 `PendingLayer` 对象具有不同的变换属性时，`Merge` 函数如何处理。
*   **与 JavaScript, HTML, CSS 的关系:** CSS 的 `transform` 属性允许对元素进行旋转、缩放、平移等操作，这些变换会影响渲染层的位置和形状。`PendingLayer` 需要能够正确合并具有不同变换的层。JavaScript 可以动态修改元素的 `transform` 属性。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入:** 两个 `PendingLayer` 对象，其中至少一个对象关联了变换属性节点。
    *   **输出:**  合并后的 `PendingLayer` 对象的边界会考虑变换的影响，能够覆盖所有被合并的内容。属性树状态会被更新。
    *   **示例 (基于测试用例 `MergeWithGuestTransform`):**
        *   home `PendingLayer` 没有变换，guest `PendingLayer` 有一个平移变换 (20, 25)。
        *   合并后，`pending_layer` 的边界被调整为 (0, 0, 70, 85)，考虑了 guest 层的平移。

**3. 处理稀疏图层 (Sparse Layers) 的合并:**

*   **功能描述:** 测试当两个待合并的 `PendingLayer` 对象在空间上距离较远时，`Merge` 函数是否会进行合并。目的是避免合并过于分散的渲染内容。
*   **与 JavaScript, HTML, CSS 的关系:** 当页面上存在多个分散的独立元素，且需要将它们的渲染信息聚合时，可能会涉及到稀疏图层的合并判断。这可能与 JavaScript 动态创建和定位元素有关。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入:** 两个 `PendingLayer` 对象，它们的边界相距较远。
    *   **输出:** `Merge` 函数返回 `false`，表示合并失败。home `PendingLayer` 对象保持不变。
    *   **示例 (基于测试用例 `DontMergeSparse`):**
        *   第一个 `PendingLayer` 的边界是 (0, 0, 30, 40)，第二个的边界是 (200, 200, 30, 40)。
        *   由于距离较远，`Merge` 操作返回 `false`。

**4. 处理不透明度 (Opaque) 信息的合并:**

*   **功能描述:** 测试合并操作如何维护和更新 `PendingLayer` 对象的不透明区域信息 (`RectKnownToBeOpaque`).
*   **与 JavaScript, HTML, CSS 的关系:** CSS 的 `opacity` 属性以及其他可能导致元素不透明的属性会影响渲染层的透明度。了解哪些区域是完全不透明的可以优化渲染过程。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入:** 两个 `PendingLayer` 对象，可能包含已知不透明的区域。
    *   **输出:** 合并后的 `PendingLayer` 对象的 `RectKnownToBeOpaque` 会反映两个原始层的不透明区域的交集和覆盖关系。如果合并后的层完全被不透明的区域覆盖，则该层也被认为是完全不透明的。
    *   **示例 (基于测试用例 `KnownOpaque`):**
        *   合并开始时，home `PendingLayer` 的 `RectKnownToBeOpaque` 为空。
        *   合并一个具有不透明区域的 guest 层后，home 层的 `RectKnownToBeOpaque` 被更新。
        *   继续合并一个完全覆盖 home 层的 guest 层后，home 层也被认为是完全不透明的。

**5. 处理纯色 (Solid Color) 图层的合并:**

*   **功能描述:** 测试合并操作如何处理表示纯色的 `PendingLayer` 对象，并计算合并后的背景色。
*   **与 JavaScript, HTML, CSS 的关系:** CSS 中设置 `background-color` 可以创建纯色背景。了解一个层是否是纯色可以进行渲染优化。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入:** 两个 `PendingLayer` 对象，其中一些可能表示纯色。
    *   **输出:** 如果合并的两个层都是纯色且颜色相同，合并后的层也是纯色。否则，合并后的层不再被认为是纯色。
    *   **示例 (基于测试用例 `SolidColor`):** 合并两个不同颜色的纯色层会导致合并后的层不再是纯色。

**6. 处理文本不透明度提示 (Text Opaqueness Hint) 的合并:**

*   **功能描述:** 测试合并操作如何处理与文本渲染相关的 `TextKnownToBeOnOpaqueBackground` 属性。这个属性指示文本是否绘制在不透明的背景上，这会影响文本渲染的优化，例如 LCD 文本渲染。
*   **与 JavaScript, HTML, CSS 的关系:**  文本内容的渲染是网页的核心部分。CSS 样式会影响文本的显示，而浏览器会尝试优化文本渲染。`TextKnownToBeOnOpaqueBackground` 是一个渲染引擎的优化提示。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入:** 两个 `PendingLayer` 对象，它们可能包含文本，并且可能有 `TextKnownToBeOnOpaqueBackground` 的标记。
    *   **输出:** 合并后的 `PendingLayer` 对象的 `TextKnownToBeOnOpaqueBackground` 属性的设置取决于合并前的两个层的状态和 `LCDTextPreference` 设置。如果 `LCDTextPreference` 是 `kStronglyPreferred`，为了保持文本渲染的优化，只有当两个层都认为文本在不透明背景上时才会合并。否则，合并后该属性可能会被设置为 `false`。
    *   **示例 (基于测试用例 `OpaqueTextAndNonOpaqueText`):** 当 `LCDTextPreference` 为 `kStronglyPreferred` 时，如果一个层的文本已知在不透明背景上，另一个不是，则不会合并。

**常见的用户或编程使用错误示例:**

1. **错误地假设稀疏图层会被合并:** 开发者可能错误地认为即使两个渲染区域相距很远，它们也会被合并到一个 `PendingLayer` 中，这可能导致对渲染性能的错误估计。
2. **在合并后错误地使用不透明区域信息:**  开发者可能会依赖合并前的 `RectKnownToBeOpaque` 信息，而没有意识到合并操作可能会改变这个信息。
3. **忽略 `LCDTextPreference` 对合并的影响:**  开发者可能没有考虑到 `LCDTextPreference` 设置会对包含文本的层的合并行为产生影响，导致在需要优化文本渲染的情况下，层没有被正确合并。
4. **在变换发生变化后没有更新相关的 `PendingLayer`:** 如果通过 JavaScript 修改了元素的变换，但没有相应地更新或重新合并相关的 `PendingLayer`，可能会导致渲染错误。
5. **错误地假设合并后的层仍然是纯色:** 在合并了不同颜色的纯色层后，开发者可能会错误地认为结果层仍然是纯色，这可能会影响后续的渲染逻辑。

总的来说，`pending_layer_test.cc` 文件详细测试了 `PendingLayer` 类的合并行为，涵盖了边界计算、变换处理、稀疏图层判断、不透明度信息维护以及文本渲染优化等方面，这些都与浏览器如何高效地渲染网页内容息息相关，并且与 HTML 结构、CSS 样式以及 JavaScript 的动态操作紧密联系。

### 提示词
```
这是目录为blink/renderer/platform/graphics/compositing/pending_layer_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/graphics/compositing/pending_layer.h"

#include <memory>

#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/graphics/paint/clip_paint_property_node.h"
#include "third_party/blink/renderer/platform/graphics/paint/effect_paint_property_node.h"
#include "third_party/blink/renderer/platform/graphics/paint/scroll_paint_property_node.h"
#include "third_party/blink/renderer/platform/graphics/paint/transform_paint_property_node.h"
#include "third_party/blink/renderer/platform/testing/paint_property_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/test_paint_artifact.h"

namespace blink {
namespace {

using testing::ElementsAre;

Vector<wtf_size_t> ChunkIndices(const PendingLayer& layer) {
  Vector<wtf_size_t> indices;
  for (auto it = layer.Chunks().begin(); it != layer.Chunks().end(); ++it)
    indices.push_back(it.IndexInPaintArtifact());
  return indices;
}

bool DefaultIsCompositedScroll(
    const TransformPaintPropertyNode& scroll_translation) {
  DCHECK(scroll_translation.ScrollNode());
  return scroll_translation.HasDirectCompositingReasons();
}

bool Merge(PendingLayer& home,
           const PendingLayer& guest,
           LCDTextPreference lcd_text_preference = LCDTextPreference::kIgnored,
           PendingLayer::IsCompositedScrollFunction is_composited_scroll =
               DefaultIsCompositedScroll) {
  return home.Merge(guest, lcd_text_preference, is_composited_scroll);
}

TEST(PendingLayerTest, Merge) {
  auto& artifact = TestPaintArtifact()
                       .Chunk()
                       .Bounds(gfx::Rect(0, 0, 30, 40))
                       .RectKnownToBeOpaque(gfx::Rect(0, 0, 30, 40))
                       .Chunk()
                       .Bounds(gfx::Rect(10, 20, 30, 40))
                       .RectKnownToBeOpaque(gfx::Rect(10, 20, 30, 40))
                       .Chunk()
                       .Bounds(gfx::Rect(-5, -25, 20, 20))
                       .RectKnownToBeOpaque(gfx::Rect(-5, -25, 20, 20))
                       .Build();

  PendingLayer pending_layer(artifact, artifact.GetPaintChunks()[0]);

  EXPECT_EQ(gfx::RectF(0, 0, 30, 40), pending_layer.BoundsForTesting());
  EXPECT_THAT(ChunkIndices(pending_layer), ElementsAre(0));
  EXPECT_EQ(pending_layer.BoundsForTesting(),
            pending_layer.RectKnownToBeOpaque());

  ASSERT_TRUE(Merge(pending_layer,
                    PendingLayer(artifact, artifact.GetPaintChunks()[1])));

  // Bounds not equal to one PaintChunk.
  EXPECT_EQ(gfx::RectF(0, 0, 40, 60), pending_layer.BoundsForTesting());
  EXPECT_THAT(ChunkIndices(pending_layer), ElementsAre(0, 1));
  EXPECT_EQ(gfx::RectF(0, 0, 30, 40), pending_layer.RectKnownToBeOpaque());

  ASSERT_TRUE(Merge(pending_layer,
                    PendingLayer(artifact, artifact.GetPaintChunks()[2])));

  EXPECT_EQ(gfx::RectF(-5, -25, 45, 85), pending_layer.BoundsForTesting());
  EXPECT_THAT(ChunkIndices(pending_layer), ElementsAre(0, 1, 2));
  EXPECT_EQ(gfx::RectF(0, 0, 30, 40), pending_layer.RectKnownToBeOpaque());
}

TEST(PendingLayerTest, MergeWithGuestTransform) {
  auto* transform = Create2DTranslation(t0(), 20, 25);
  auto& artifact = TestPaintArtifact()
                       .Chunk()
                       .Bounds(gfx::Rect(0, 0, 30, 40))
                       .Chunk(*transform, c0(), e0())
                       .Bounds(gfx::Rect(0, 0, 50, 60))
                       .Build();

  PendingLayer pending_layer(artifact, artifact.GetPaintChunks()[0]);
  ASSERT_TRUE(Merge(pending_layer,
                    PendingLayer(artifact, artifact.GetPaintChunks()[1])));
  EXPECT_EQ(gfx::RectF(0, 0, 70, 85), pending_layer.BoundsForTesting());
  EXPECT_EQ(PropertyTreeState::Root(), pending_layer.GetPropertyTreeState());
}

TEST(PendingLayerTest, MergeWithHomeTransform) {
  auto* transform = Create2DTranslation(t0(), 20, 25);
  auto& artifact = TestPaintArtifact()
                       .Chunk(*transform, c0(), e0())
                       .Bounds(gfx::Rect(0, 0, 30, 40))
                       .Chunk()
                       .Bounds(gfx::Rect(0, 0, 50, 60))
                       .Build();

  PendingLayer pending_layer(artifact, artifact.GetPaintChunks()[0]);
  ASSERT_TRUE(Merge(pending_layer,
                    PendingLayer(artifact, artifact.GetPaintChunks()[1])));
  EXPECT_EQ(gfx::RectF(0, 0, 50, 65), pending_layer.BoundsForTesting());
  EXPECT_EQ(PropertyTreeState::Root(), pending_layer.GetPropertyTreeState());
}

TEST(PendingLayerTest, MergeWithBothTransforms) {
  auto* t1 = Create2DTranslation(t0(), 20, 25);
  auto* t2 = Create2DTranslation(t0(), -20, -25);
  auto& artifact = TestPaintArtifact()
                       .Chunk(*t1, c0(), e0())
                       .Bounds(gfx::Rect(0, 0, 30, 40))
                       .Chunk(*t2, c0(), e0())
                       .Bounds(gfx::Rect(0, 0, 50, 60))
                       .Build();

  PendingLayer pending_layer(artifact, artifact.GetPaintChunks()[0]);
  ASSERT_TRUE(Merge(pending_layer,
                    PendingLayer(artifact, artifact.GetPaintChunks()[1])));
  EXPECT_EQ(gfx::RectF(-20, -25, 70, 90), pending_layer.BoundsForTesting());
  EXPECT_EQ(PropertyTreeState::Root(), pending_layer.GetPropertyTreeState());
}

TEST(PendingLayerTest, MergeSparseTinyLayers) {
  auto& artifact = TestPaintArtifact()
                       .Chunk()
                       .Bounds(gfx::Rect(0, 0, 3, 4))
                       .RectKnownToBeOpaque(gfx::Rect(0, 0, 3, 4))
                       .Chunk()
                       .Bounds(gfx::Rect(20, 20, 3, 4))
                       .RectKnownToBeOpaque(gfx::Rect(20, 20, 3, 4))
                       .Build();

  PendingLayer pending_layer(artifact, artifact.GetPaintChunks()[0]);
  ASSERT_TRUE(Merge(pending_layer,
                    PendingLayer(artifact, artifact.GetPaintChunks()[1])));
  EXPECT_EQ(gfx::RectF(0, 0, 23, 24), pending_layer.BoundsForTesting());
  EXPECT_THAT(ChunkIndices(pending_layer), ElementsAre(0, 1));
}

TEST(PendingLayerTest, DontMergeSparse) {
  auto& artifact = TestPaintArtifact()
                       .Chunk()
                       .Bounds(gfx::Rect(0, 0, 30, 40))
                       .RectKnownToBeOpaque(gfx::Rect(0, 0, 30, 40))
                       .Chunk()
                       .Bounds(gfx::Rect(200, 200, 30, 40))
                       .RectKnownToBeOpaque(gfx::Rect(200, 200, 30, 40))
                       .Build();

  PendingLayer pending_layer(artifact, artifact.GetPaintChunks()[0]);
  ASSERT_FALSE(Merge(pending_layer,
                     PendingLayer(artifact, artifact.GetPaintChunks()[1])));
  EXPECT_EQ(gfx::RectF(0, 0, 30, 40), pending_layer.BoundsForTesting());
  EXPECT_EQ(artifact.GetPaintChunks()[0].properties,
            pending_layer.GetPropertyTreeState());
  EXPECT_THAT(ChunkIndices(pending_layer), ElementsAre(0));
}

TEST(PendingLayerTest, PendingLayerDontMergeSparseWithTransforms) {
  auto* t1 = Create2DTranslation(t0(), 20, 25);
  auto* t2 = Create2DTranslation(t0(), 1000, 1000);
  auto& artifact = TestPaintArtifact()
                       .Chunk(*t1, c0(), e0())
                       .Bounds(gfx::Rect(0, 0, 30, 40))
                       .Chunk(*t2, c0(), e0())
                       .Bounds(gfx::Rect(0, 0, 50, 60))
                       .Build();

  PendingLayer pending_layer(artifact, artifact.GetPaintChunks()[0]);
  ASSERT_FALSE(Merge(pending_layer,
                     PendingLayer(artifact, artifact.GetPaintChunks()[1])));
  EXPECT_EQ(gfx::RectF(0, 0, 30, 40), pending_layer.BoundsForTesting());
  EXPECT_EQ(artifact.GetPaintChunks()[0].properties,
            pending_layer.GetPropertyTreeState());
  EXPECT_THAT(ChunkIndices(pending_layer), ElementsAre(0));
}

TEST(PendingLayerTest, DontMergeSparseInCompositedEffect) {
  auto* t1 = Create2DTranslation(t0(), 20, 25);
  auto* e1 =
      CreateOpacityEffect(e0(), 1.0f, CompositingReason::kWillChangeOpacity);
  auto* t2 = Create2DTranslation(t0(), 1000, 1000);
  auto& artifact = TestPaintArtifact()
                       .Chunk(*t1, c0(), *e1)
                       .Bounds(gfx::Rect(0, 0, 30, 40))
                       .Chunk(*t2, c0(), *e1)
                       .Bounds(gfx::Rect(0, 0, 50, 60))
                       .Build();

  PendingLayer pending_layer(artifact, artifact.GetPaintChunks()[0]);
  ASSERT_FALSE(Merge(pending_layer,
                     PendingLayer(artifact, artifact.GetPaintChunks()[1])));
  EXPECT_EQ(gfx::RectF(0, 0, 30, 40), pending_layer.BoundsForTesting());
  EXPECT_EQ(artifact.GetPaintChunks()[0].properties,
            pending_layer.GetPropertyTreeState());
  EXPECT_THAT(ChunkIndices(pending_layer), ElementsAre(0));
}

TEST(PendingLayerTest, MergeSparseInNonCompositedEffect) {
  auto* t1 = Create2DTranslation(t0(), 20, 25);
  auto* t2 = Create2DTranslation(t0(), 1000, 1000);
  auto* e1 = CreateOpacityEffect(e0(), 1.0f, CompositingReason::kNone);
  auto& artifact = TestPaintArtifact()
                       .Chunk(*t1, c0(), *e1)
                       .Bounds(gfx::Rect(0, 0, 30, 40))
                       .Chunk(*t2, c0(), *e1)
                       .Bounds(gfx::Rect(0, 0, 50, 60))
                       .Build();

  PendingLayer pending_layer(artifact, artifact.GetPaintChunks()[0]);
  EXPECT_FALSE(Merge(pending_layer,
                     PendingLayer(artifact, artifact.GetPaintChunks()[1])));
}

TEST(PendingLayerTest, KnownOpaque) {
  auto& artifact = TestPaintArtifact()
                       .Chunk()
                       .Bounds(gfx::Rect(0, 0, 30, 40))
                       .Chunk()
                       .Bounds(gfx::Rect(0, 0, 25, 35))
                       .RectKnownToBeOpaque(gfx::Rect(0, 0, 25, 35))
                       .Chunk()
                       .Bounds(gfx::Rect(0, 0, 50, 60))
                       .RectKnownToBeOpaque(gfx::Rect(0, 0, 50, 60))
                       .Build();

  PendingLayer pending_layer(artifact, artifact.GetPaintChunks()[0]);
  EXPECT_TRUE(pending_layer.RectKnownToBeOpaque().IsEmpty());

  ASSERT_TRUE(Merge(pending_layer,
                    PendingLayer(artifact, artifact.GetPaintChunks()[1])));
  // Chunk 2 doesn't cover the entire layer, so not opaque.
  EXPECT_EQ(gfx::RectF(0, 0, 25, 35), pending_layer.RectKnownToBeOpaque());
  EXPECT_NE(pending_layer.BoundsForTesting(),
            pending_layer.RectKnownToBeOpaque());

  ASSERT_TRUE(Merge(pending_layer,
                    PendingLayer(artifact, artifact.GetPaintChunks()[2])));
  // Chunk 3 covers the entire layer, so now it's opaque.
  EXPECT_EQ(gfx::RectF(0, 0, 50, 60), pending_layer.BoundsForTesting());
  EXPECT_EQ(pending_layer.BoundsForTesting(),
            pending_layer.RectKnownToBeOpaque());
}

TEST(PendingLayerTest, SolidColor) {
  auto& artifact =
      TestPaintArtifact()
          .Chunk()
          .RectDrawing(gfx::Rect(100, 100, 250, 250), Color::kBlack)
          .IsSolidColor()
          .Chunk()
          .RectDrawing(gfx::Rect(100, 100, 150, 150), Color::kWhite)
          .IsSolidColor()
          .Chunk()
          .RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kBlack)
          .RectDrawing(gfx::Rect(100, 100, 150, 150), Color::kWhite)
          .Build();

  PendingLayer pending_layer1(artifact, artifact.GetPaintChunks()[0]);
  EXPECT_TRUE(pending_layer1.IsSolidColor());
  EXPECT_EQ(SkColors::kBlack, pending_layer1.ComputeBackgroundColor());
  PendingLayer pending_layer2(artifact, artifact.GetPaintChunks()[1]);
  EXPECT_TRUE(pending_layer2.IsSolidColor());
  EXPECT_EQ(SkColors::kWhite, pending_layer2.ComputeBackgroundColor());
  PendingLayer pending_layer3(artifact, artifact.GetPaintChunks()[2]);
  EXPECT_FALSE(pending_layer3.IsSolidColor());
  EXPECT_TRUE(Merge(pending_layer1, pending_layer2));
  EXPECT_FALSE(pending_layer1.IsSolidColor());
}

class PendingLayerTextOpaquenessTest
    : public testing::Test,
      public testing::WithParamInterface<LCDTextPreference> {
 protected:
  LCDTextPreference GetLCDTextPreference() const { return GetParam(); }
};

INSTANTIATE_TEST_SUITE_P(
    All,
    PendingLayerTextOpaquenessTest,
    ::testing::Values(LCDTextPreference::kStronglyPreferred,
                      LCDTextPreference::kIgnored));

TEST_P(PendingLayerTextOpaquenessTest, OpaqueTextAndOpaqueText) {
  auto& artifact =
      TestPaintArtifact()
          .Chunk(t0(), c0(), e0())
          .RectDrawing(gfx::Rect(100, 100, 250, 250), Color::kBlack)
          .HasText()
          .TextKnownToBeOnOpaqueBackground()
          .Chunk(t0(), c0(), e0())
          .RectDrawing(gfx::Rect(200, 200, 300, 300), Color::kBlack)
          .HasText()
          .TextKnownToBeOnOpaqueBackground()
          .Build();
  PendingLayer layer_a(artifact, artifact.GetPaintChunks()[0]);
  PendingLayer layer_b(artifact, artifact.GetPaintChunks()[1]);
  ASSERT_TRUE(Merge(layer_a, layer_b, GetLCDTextPreference()));
  EXPECT_EQ(gfx::RectF(100, 100, 400, 400), layer_a.BoundsForTesting());
  EXPECT_TRUE(layer_a.TextKnownToBeOnOpaqueBackground());
}

TEST_P(PendingLayerTextOpaquenessTest, NonOpaqueTextAndOpaqueText) {
  auto& artifact =
      TestPaintArtifact()
          .Chunk(t0(), c0(), e0())
          .RectDrawing(gfx::Rect(100, 100, 250, 250), Color::kBlack)
          .HasText()
          .Chunk(t0(), c0(), e0())
          .RectDrawing(gfx::Rect(200, 200, 300, 300), Color::kBlack)
          .HasText()
          .TextKnownToBeOnOpaqueBackground()
          .Build();
  PendingLayer layer_a(artifact, artifact.GetPaintChunks()[0]);
  PendingLayer layer_b(artifact, artifact.GetPaintChunks()[1]);
  bool merged = Merge(layer_a, layer_b, GetLCDTextPreference());
  if (GetLCDTextPreference() == LCDTextPreference::kStronglyPreferred) {
    // Not merged because merging would lose TextKnownToBeOnOpaqueBackground().
    ASSERT_FALSE(merged);
  } else {
    ASSERT_TRUE(merged);
    EXPECT_EQ(gfx::RectF(100, 100, 400, 400), layer_a.BoundsForTesting());
    EXPECT_FALSE(layer_a.TextKnownToBeOnOpaqueBackground());
  }
}

TEST_P(PendingLayerTextOpaquenessTest, OpaqueTextAndNonOpaqueText) {
  auto& artifact =
      TestPaintArtifact()
          .Chunk(t0(), c0(), e0())
          .RectDrawing(gfx::Rect(100, 100, 250, 250), Color::kBlack)
          .HasText()
          .TextKnownToBeOnOpaqueBackground()
          .Chunk(t0(), c0(), e0())
          .RectDrawing(gfx::Rect(200, 200, 300, 300), Color::kBlack)
          .HasText()
          .Build();
  PendingLayer layer_a(artifact, artifact.GetPaintChunks()[0]);
  PendingLayer layer_b(artifact, artifact.GetPaintChunks()[1]);
  bool merged = Merge(layer_a, layer_b, GetLCDTextPreference());
  if (GetLCDTextPreference() == LCDTextPreference::kStronglyPreferred) {
    // Not merged because merging would lose TextKnownToBeOnOpaqueBackground().
    ASSERT_FALSE(merged);
  } else {
    ASSERT_TRUE(merged);
    EXPECT_EQ(gfx::RectF(100, 100, 400, 400), layer_a.BoundsForTesting());
    EXPECT_FALSE(layer_a.TextKnownToBeOnOpaqueBackground());
  }
}

TEST_P(PendingLayerTextOpaquenessTest, NonOpaqueTextAndOpaqueTextCovered) {
  auto& artifact =
      TestPaintArtifact()
          .Chunk(t0(), c0(), e0())
          .RectDrawing(gfx::Rect(200, 200, 100, 100), Color::kBlack)
          .HasText()
          .Chunk(t0(), c0(), e0())
          .RectDrawing(gfx::Rect(100, 100, 300, 300), Color::kBlack)
          .RectKnownToBeOpaque(gfx::Rect(200, 200, 100, 100))
          .HasText()
          .TextKnownToBeOnOpaqueBackground()
          .Build();
  PendingLayer layer_a(artifact, artifact.GetPaintChunks()[0]);
  PendingLayer layer_b(artifact, artifact.GetPaintChunks()[1]);
  ASSERT_TRUE(Merge(layer_a, layer_b, GetLCDTextPreference()));
  EXPECT_EQ(gfx::RectF(100, 100, 300, 300), layer_a.BoundsForTesting());
  EXPECT_EQ(gfx::RectF(200, 200, 100, 100), layer_a.RectKnownToBeOpaque());
  EXPECT_TRUE(layer_a.TextKnownToBeOnOpaqueBackground());
}

TEST_P(PendingLayerTextOpaquenessTest, OpaqueTextAndNonOpaqueTextCovered) {
  auto& artifact =
      TestPaintArtifact()
          .Chunk(t0(), c0(), e0())
          .RectDrawing(gfx::Rect(100, 100, 250, 250), Color::kBlack)
          .RectKnownToBeOpaque(gfx::Rect(100, 100, 210, 210))
          .HasText()
          .TextKnownToBeOnOpaqueBackground()
          .Chunk(t0(), c0(), e0())
          .RectDrawing(gfx::Rect(200, 200, 100, 100), Color::kBlack)
          .HasText()
          .Build();
  PendingLayer layer_a(artifact, artifact.GetPaintChunks()[0]);
  PendingLayer layer_b(artifact, artifact.GetPaintChunks()[1]);
  ASSERT_TRUE(Merge(layer_a, layer_b, GetLCDTextPreference()));
  EXPECT_EQ(gfx::RectF(100, 100, 250, 250), layer_a.BoundsForTesting());
  EXPECT_EQ(gfx::RectF(100, 100, 210, 210), layer_a.RectKnownToBeOpaque());
  EXPECT_TRUE(layer_a.TextKnownToBeOnOpaqueBackground());
}

TEST_P(PendingLayerTextOpaquenessTest, NoTextAndOpaqueText) {
  auto& artifact =
      TestPaintArtifact()
          .Chunk(t0(), c0(), e0())
          .RectDrawing(gfx::Rect(100, 100, 250, 250), Color::kBlack)
          .RectKnownToBeOpaque(gfx::Rect(100, 100, 210, 210))
          .Chunk(t0(), c0(), e0())
          .RectDrawing(gfx::Rect(200, 200, 300, 300), Color::kBlack)
          .HasText()
          .TextKnownToBeOnOpaqueBackground()
          .Build();
  PendingLayer layer_a(artifact, artifact.GetPaintChunks()[0]);
  PendingLayer layer_b(artifact, artifact.GetPaintChunks()[1]);
  ASSERT_TRUE(Merge(layer_a, layer_b, GetLCDTextPreference()));
  EXPECT_EQ(gfx::RectF(100, 100, 400, 400), layer_a.BoundsForTesting());
  EXPECT_EQ(gfx::RectF(100, 100, 210, 210), layer_a.RectKnownToBeOpaque());
  EXPECT_TRUE(layer_a.TextKnownToBeOnOpaqueBackground());
}

TEST_P(PendingLayerTextOpaquenessTest, OpaqueTextAndNoText) {
  auto& artifact =
      TestPaintArtifact()
          .Chunk(t0(), c0(), e0())
          .RectDrawing(gfx::Rect(100, 100, 250, 250), Color::kBlack)
          .RectKnownToBeOpaque(gfx::Rect(100, 100, 210, 210))
          .HasText()
          .TextKnownToBeOnOpaqueBackground()
          .Chunk(t0(), c0(), e0())
          .RectDrawing(gfx::Rect(200, 200, 300, 300), Color::kBlack)
          .Build();
  PendingLayer layer_a(artifact, artifact.GetPaintChunks()[0]);
  PendingLayer layer_b(artifact, artifact.GetPaintChunks()[1]);
  ASSERT_TRUE(Merge(layer_a, layer_b, GetLCDTextPreference()));
  EXPECT_EQ(gfx::RectF(100, 100, 400, 400), layer_a.BoundsForTesting());
  EXPECT_EQ(gfx::RectF(100, 100, 210, 210), layer_a.RectKnownToBeOpaque());
  EXPECT_TRUE(layer_a.TextKnownToBeOnOpaqueBackground());
}

TEST_P(PendingLayerTextOpaquenessTest, NonOpaqueNoTextAndNonOpaqueText) {
  auto& artifact =
      TestPaintArtifact()
          .Chunk(t0(), c0(), e0())
          .RectDrawing(gfx::Rect(100, 100, 250, 250), Color::kBlack)
          .Chunk(t0(), c0(), e0())
          .RectDrawing(gfx::Rect(200, 200, 300, 300), Color::kBlack)
          .HasText()
          .Build();
  PendingLayer layer_a(artifact, artifact.GetPaintChunks()[0]);
  PendingLayer layer_b(artifact, artifact.GetPaintChunks()[1]);
  ASSERT_TRUE(Merge(layer_a, layer_b, GetLCDTextPreference()));
  EXPECT_EQ(gfx::RectF(100, 100, 400, 400), layer_a.BoundsForTesting());
  EXPECT_FALSE(layer_a.TextKnownToBeOnOpaqueBackground());
}

TEST_P(PendingLayerTextOpaquenessTest, NonOpaqueTextAndNonOpaqueNoText) {
  auto& artifact =
      TestPaintArtifact()
          .Chunk(t0(), c0(), e0())
          .RectDrawing(gfx::Rect(100, 100, 250, 250), Color::kBlack)
          .HasText()
          .Chunk(t0(), c0(), e0())
          .RectDrawing(gfx::Rect(200, 200, 300, 300), Color::kBlack)
          .Build();
  PendingLayer layer_a(artifact, artifact.GetPaintChunks()[0]);
  PendingLayer layer_b(artifact, artifact.GetPaintChunks()[1]);
  ASSERT_TRUE(Merge(layer_a, layer_b, GetLCDTextPreference()));
  EXPECT_EQ(gfx::RectF(100, 100, 400, 400), layer_a.BoundsForTesting());
  EXPECT_FALSE(layer_a.TextKnownToBeOnOpaqueBackground());
}

TEST_P(PendingLayerTextOpaquenessTest, OpaqueNoTextAndNonOpaqueText) {
  auto& artifact =
      TestPaintArtifact()
          .Chunk(t0(), c0(), e0())
          .RectDrawing(gfx::Rect(100, 100, 250, 250), Color::kBlack)
          .RectKnownToBeOpaque(gfx::Rect(100, 100, 210, 210))
          .Chunk(t0(), c0(), e0())
          .RectDrawing(gfx::Rect(200, 200, 100, 100), Color::kBlack)
          .HasText()
          .Build();
  PendingLayer layer_a(artifact, artifact.GetPaintChunks()[0]);
  PendingLayer layer_b(artifact, artifact.GetPaintChunks()[1]);
  ASSERT_TRUE(Merge(layer_a, layer_b, GetLCDTextPreference()));
  EXPECT_EQ(gfx::RectF(100, 100, 250, 250), layer_a.BoundsForTesting());
  EXPECT_EQ(gfx::RectF(100, 100, 210, 210), layer_a.RectKnownToBeOpaque());
  EXPECT_TRUE(layer_a.TextKnownToBeOnOpaqueBackground());
}

TEST_P(PendingLayerTextOpaquenessTest, NonOpaqueTextAndOpaqueNoText) {
  auto& artifact =
      TestPaintArtifact()
          .Chunk(t0(), c0(), e0())
          .RectDrawing(gfx::Rect(200, 200, 100, 100), Color::kBlack)
          .HasText()
          .Chunk(t0(), c0(), e0())
          .RectDrawing(gfx::Rect(100, 100, 250, 250), Color::kBlack)
          .RectKnownToBeOpaque(gfx::Rect(100, 100, 210, 210))
          .Build();
  PendingLayer layer_a(artifact, artifact.GetPaintChunks()[0]);
  PendingLayer layer_b(artifact, artifact.GetPaintChunks()[1]);
  ASSERT_TRUE(Merge(layer_a, layer_b, GetLCDTextPreference()));
  EXPECT_EQ(gfx::RectF(100, 100, 250, 250), layer_a.BoundsForTesting());
  EXPECT_EQ(gfx::RectF(100, 100, 210, 210), layer_a.RectKnownToBeOpaque());
  EXPECT_TRUE(layer_a.TextKnownToBeOnOpaqueBackground());
}

TEST_P(PendingLayerTextOpaquenessTest, UnitedClippedToOpaque) {
  // Though the second chunk has text not on opaque background, and it's not
  // fully covered by the opaque rect of the first chunk, the non-opaque area
  // is not visible in the final layer, so we still allow the merge.
  auto* clip1 = CreateClip(c0(), t0(), FloatRoundedRect(175, 175, 100, 100));
  auto& artifact =
      TestPaintArtifact()
          .Chunk(t0(), *clip1, e0())
          .RectDrawing(gfx::Rect(100, 100, 250, 250), Color::kBlack)
          .RectKnownToBeOpaque(gfx::Rect(100, 100, 210, 210))
          .HasText()
          .TextKnownToBeOnOpaqueBackground()
          .Chunk(t0(), *clip1, e0())
          .RectDrawing(gfx::Rect(200, 200, 300, 300), Color::kBlack)
          .HasText()
          .Build();
  PendingLayer layer_a(artifact, artifact.GetPaintChunks()[0]);
  PendingLayer layer_b(artifact, artifact.GetPaintChunks()[1]);
  ASSERT_TRUE(Merge(layer_a, layer_b, GetLCDTextPreference()));
  EXPECT_EQ(gfx::RectF(175, 175, 100, 100), layer_a.BoundsForTesting());
  EXPECT_EQ(gfx::RectF(175, 175, 100, 100), layer_a.RectKnownToBeOpaque());
  EXPECT_TRUE(layer_a.TextKnownToBeOnOpaqueBackground());
}

}  // namespace
}  // namespace blink
```