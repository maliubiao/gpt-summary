Response:
Let's break down the thought process for analyzing this C++ test file and extracting the relevant information.

1. **Understanding the Core Task:** The primary goal is to understand what the `chunk_to_layer_mapper_test.cc` file does. The filename itself is a strong hint: it's a *test* file for something called `ChunkToLayerMapper`. This immediately suggests the file's purpose is to verify the functionality of that mapper.

2. **Identifying the Tested Class:**  The `#include` statements at the beginning of the file confirm the class under test: `ChunkToLayerMapper` in `blink/renderer/platform/graphics/compositing/chunk_to_layer_mapper.h`. Knowing the class name is crucial for understanding the tests' focus.

3. **Analyzing the Test Structure:** The file uses the Google Test framework (`testing/gtest/include/gtest/gtest.h`). This means we should look for `TEST_F` macros, which define individual test cases. The `ChunkToLayerMapperTest` class, derived from `testing::Test`, sets up the testing environment.

4. **Deconstructing Individual Tests:**  Let's examine a few test cases to understand their purpose:

    * **`OneChunkUsingLayerState`:** This test creates a `ChunkToLayerMapper` with a specific layer state and offset. It then switches to a single `PaintChunk` that also uses the same layer state. The assertions check if the mapper's `Transform()`, `ClipRect()`, and `MapVisualRect()` methods behave as expected. The name "UsingLayerState" suggests it's testing the case where the chunk inherits properties from the layer.

    * **`TwoChunkUsingLayerState`:**  Similar to the previous test, but it switches between two chunks with the same layer state. This likely checks if the mapper correctly handles multiple switches without accumulating transformations or other state inappropriately.

    * **`TwoChunkSameState`:** This test uses two chunks with the *same* non-default `PropertyTreeState` (involving a scale and clip). The assertions verify that the mapper correctly applies these shared properties. This tests how the mapper handles consistency across chunks.

    * **`TwoChunkDifferentState`:**  This test introduces chunks with *different* `PropertyTreeState` configurations. The assertions check if the mapper updates its internal state correctly when switching between chunks with varying transformations and clips. This is a crucial test for the mapper's ability to adapt to different rendering contexts.

    * **`SlowPath`:**  This test introduces the concept of a "slow path" related to filters that move pixels (like blur). It creates chunks with and without such filters and checks the `HasFilterThatMovesPixels()` method and how `MapVisualRect()` behaves in these scenarios. The comments within this test are particularly helpful in understanding the intent.

    * **`SwitchToSiblingEffect`:** This test case focuses on switching between chunks that have different, but related, effect properties (specifically opacity). It aims to verify that the mapper handles these transitions correctly, even when the underlying layer state is the same.

5. **Identifying Key Concepts and Functionality:** Based on the test names and assertions, we can deduce the core functionalities of `ChunkToLayerMapper`:

    * **Mapping Chunks to Layers:** The name itself suggests this is the primary function.
    * **Handling Property Tree States:**  The tests extensively use `PropertyTreeState`, indicating that the mapper is responsible for managing and applying properties like transforms, clips, and effects associated with paint chunks.
    * **Transformations:**  The `Transform()` method and the `MapVisualRect()` function demonstrate the mapper's role in applying transformations to coordinates.
    * **Clipping:** The `ClipRect()` method reveals its handling of clipping regions.
    * **Filters:** The "SlowPath" test highlights the special handling of filters that can shift pixel positions.

6. **Relating to Web Technologies (JavaScript, HTML, CSS):**  The properties being manipulated (transforms, clips, filters, opacity) directly correspond to CSS properties. The underlying rendering pipeline of a web browser uses these concepts to draw web pages. Therefore, `ChunkToLayerMapper` plays a role in how CSS styles are translated into actual visual output.

7. **Inferring Logic and Assumptions:**  By looking at how the tests are structured, we can infer some of the mapper's internal logic. For example, the "SlowPath" test implies that applying certain filters requires a more complex (and potentially less efficient) rendering process. The tests with different `PropertyTreeState` values suggest the mapper needs to cache or update its internal state when switching between chunks.

8. **Considering Potential Errors:** The tests implicitly reveal potential usage errors. If a developer incorrectly configures the `PropertyTreeState` for different chunks within the same layer, the `ChunkToLayerMapper` might produce unexpected transformations or clipping. The "SlowPath" test also highlights that using certain filters can have performance implications.

9. **Structuring the Output:** Finally, we need to organize the extracted information into a clear and understandable format, addressing all parts of the original request (functionality, relationship to web technologies, logical reasoning, and potential errors). Using bullet points and clear examples makes the information easier to digest.
这个C++源代码文件 `chunk_to_layer_mapper_test.cc` 是 Chromium Blink 渲染引擎的一部分，其主要功能是 **测试 `ChunkToLayerMapper` 类的功能**。

`ChunkToLayerMapper` 的作用是将渲染过程中的 "chunk"（`PaintChunk`，可以理解为一部分绘制指令的集合）映射到最终合成的 "layer" (图形层)。它负责管理和转换与每个 chunk 相关的属性，例如变换（transform）、裁剪（clip）等，以便正确地将 chunk 的内容绘制到对应的层上。

下面我们详细列举一下 `chunk_to_layer_mapper_test.cc` 的功能，并尝试关联到 JavaScript, HTML, CSS 的功能：

**`chunk_to_layer_mapper_test.cc` 的功能:**

1. **创建 `ChunkToLayerMapper` 实例并进行测试:**  文件中定义了一个测试类 `ChunkToLayerMapperTest`，它继承自 `testing::Test`，这是 Google Test 框架的标准用法。  测试用例通过创建 `ChunkToLayerMapper` 的实例，并调用其方法来验证其行为。

2. **测试在单个 chunk 场景下的映射:** `TEST_F(ChunkToLayerMapperTest, OneChunkUsingLayerState)` 测试用例验证了当只有一个 chunk 且其状态与所在层的状态相同时，`ChunkToLayerMapper` 的行为。它检查了变换矩阵、裁剪区域和视觉矩形的映射是否正确。

3. **测试在多个相同状态 chunk 场景下的映射:** `TEST_F(ChunkToLayerMapperTest, TwoChunkUsingLayerState)` 和 `TEST_F(ChunkToLayerMapperTest, TwoChunkSameState)` 测试用例验证了当有多个 chunk，且它们的属性状态与所在层相同或彼此相同时，`ChunkToLayerMapper` 在切换 chunk 时是否能保持正确的映射关系。

4. **测试在多个不同状态 chunk 场景下的映射:** `TEST_F(ChunkToLayerMapperTest, TwoChunkDifferentState)` 测试用例着重测试了当切换到具有不同属性状态的 chunk 时，`ChunkToLayerMapper` 是否能正确更新其内部状态，并进行相应的变换和裁剪计算。

5. **测试涉及 "慢路径" 的场景:** `TEST_F(ChunkToLayerMapperTest, SlowPath)` 测试用例测试了当 chunk 包含会移动像素的滤镜效果（例如模糊）时，`ChunkToLayerMapper` 的行为。在这种情况下，渲染引擎可能需要采用更复杂的 "慢路径" 进行处理。这个测试用例验证了 `HasFilterThatMovesPixels()` 方法的返回值，以及变换和裁剪的计算是否正确。

6. **测试切换到具有相似效果的 chunk:** `TEST_F(ChunkToLayerMapperTest, SwitchToSiblingEffect)` 测试了当切换到具有相同类型但参数不同的效果的 chunk 时（例如，不同的透明度值），`ChunkToLayerMapper` 的行为。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`ChunkToLayerMapper` 的功能直接关系到浏览器如何将 HTML 结构和 CSS 样式渲染到屏幕上。

* **CSS 变换 (transform):**  CSS 的 `transform` 属性（例如 `translate`, `rotate`, `scale`）会创建变换矩阵。`ChunkToLayerMapper` 负责将这些 CSS 变换应用到相应的 chunk 上。
    * **举例:**  一个 HTML 元素通过 CSS 设置了 `transform: translateX(10px);`。当渲染引擎处理这个元素时，它会创建一个包含这个变换信息的 `PaintChunk`。 `ChunkToLayerMapper` 会将这个变换应用到该 chunk，确保元素在屏幕上向右偏移 10 像素。
    * **假设输入与输出 (对于 `TwoChunkDifferentState` 测试中涉及变换的部分):**
        * **假设输入:**
            * Layer 的基础偏移: `gfx::Vector2dF(10, 20)`
            * `chunk1` 的变换: `scale(2)`
            * `chunk2` 的变换: 继承 `chunk1` 的变换并额外 `translate(20px, 30px)`
        * **输出:**
            * 切换到 `chunk1` 后 `mapper.Transform()` 应该返回一个先缩放 2 倍，再平移 (-10, -20) 的矩阵。
            * 切换到 `chunk2` 后 `mapper.Transform()` 应该返回一个先缩放 2 倍，再平移 (20, 30)，最后再平移 (-10, -20) 的矩阵。

* **CSS 裁剪 (clip-path, overflow: hidden):** CSS 的裁剪属性会定义元素的可视区域。`ChunkToLayerMapper` 需要处理这些裁剪信息。
    * **举例:** 一个 HTML 元素的 CSS 设置了 `overflow: hidden; width: 100px; height: 100px;`。 渲染引擎会创建一个裁剪区域限制该元素的绘制范围。`ChunkToLayerMapper` 会记录这个裁剪区域，确保超出 100x100 范围的内容不会被绘制。
    * **假设输入与输出 (对于 `TwoChunkDifferentState` 测试中涉及裁剪的部分):**
        * **假设输入:**
            * Layer 的基础裁剪为空。
            * `chunk1` 的裁剪: 矩形区域 `(10, 10, 100, 100)`
            * `chunk2` 的裁剪: 相对于 `chunk2` 的变换，矩形区域 `(0, 0, 20, 20)`
        * **输出:**
            * 切换到 `chunk1` 后 `mapper.ClipRect()` 应该返回一个表示 `(0, -10, 100, 100)` 的裁剪矩形（考虑了 Layer 的偏移）。
            * 切换到 `chunk2` 后 `mapper.ClipRect()` 应该返回一个表示 `(30, 40, 40, 40)` 的裁剪矩形（考虑了 Layer 的偏移和 `chunk2` 的变换）。

* **CSS 滤镜 (filter):** CSS 的 `filter` 属性可以添加各种视觉效果，例如模糊、亮度调整等。某些滤镜（如模糊）会改变元素的边界，需要特殊处理。
    * **举例:**  一个 HTML 元素设置了 `filter: blur(5px);`。 `ChunkToLayerMapper` 需要知道这个滤镜会影响绘制区域，并可能需要调整边界。`SlowPath` 测试用例就是测试这种情况。
    * **假设输入与输出 (对于 `SlowPath` 测试中涉及滤镜的部分):**
        * **假设输入:**
            * Layer 的基础偏移: `gfx::Vector2dF(10, 20)`
            * `chunk2` 应用了 `blur(20px)` 滤镜。
        * **输出:**
            * 切换到 `chunk2` 后 `HasFilterThatMovesPixels(mapper)` 应该返回 `true`。
            * `mapper.ClipRect()` 应该返回一个无限大的矩形（因为模糊会影响所有区域）。
            * `mapper.MapVisualRect(gfx::Rect(30, 30, 88, 99))` 映射后的矩形会因为模糊效果而扩大，例如 `gfx::Rect(-40, -50, 208, 219)`。

* **CSS 透明度 (opacity):** CSS 的 `opacity` 属性会影响元素的透明度。这可以通过效果属性节点传递给 `ChunkToLayerMapper`。
    * **举例:** 一个 HTML 元素的 CSS 设置了 `opacity: 0.5;`。`ChunkToLayerMapper` 会接收到这个透明度信息，并将其应用到该 chunk 的绘制过程中。

**用户或编程常见的使用错误 (在 Blink 内部开发中):**

由于 `ChunkToLayerMapper` 是 Blink 内部的组件，用户一般不会直接与其交互。然而，在 Blink 内部开发中，可能会出现以下使用错误：

1. **没有正确更新 `PropertyTreeState`:**  如果在切换 chunk 时，没有正确地更新与 chunk 相关的 `PropertyTreeState`（包括变换、裁剪、效果等），会导致 `ChunkToLayerMapper` 使用过时的信息进行映射，从而导致渲染错误。
    * **举例:**  一个开发者在创建新的 `PaintChunk` 时，错误地使用了上一个 chunk 的变换属性，导致新 chunk 的内容被错误地定位。

2. **在需要 "慢路径" 处理时使用了 "快路径" 逻辑:** 当 chunk 包含会移动像素的滤镜时，需要使用特定的 "慢路径" 处理。如果开发者错误地假设可以使用 "快路径" 逻辑，可能会导致渲染结果不正确或性能问题。
    * **举例:**  一个开发者在处理带有模糊效果的 chunk 时，仍然按照没有滤镜的情况计算裁剪区域，导致模糊效果被裁剪掉。

3. **对 Layer 的基础状态理解有误:** `ChunkToLayerMapper` 的工作是基于其所在 Layer 的基础状态进行的。如果开发者对 Layer 的变换、裁剪等属性的理解有误，可能会导致 chunk 的映射结果不符合预期。
    * **举例:** 开发者错误地认为 Layer 没有应用任何变换，但在创建 chunk 的 mapper 时没有考虑 Layer 的实际变换，导致 chunk 的最终位置偏移不正确。

**总结:**

`chunk_to_layer_mapper_test.cc` 通过一系列单元测试，细致地验证了 `ChunkToLayerMapper` 在各种场景下的行为，确保了 Blink 渲染引擎能够正确地将不同的渲染 "chunk" 映射到最终的图形层上，并正确处理与之相关的 CSS 属性。这对于保证网页的正确渲染至关重要。

### 提示词
```
这是目录为blink/renderer/platform/graphics/compositing/chunk_to_layer_mapper_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/graphics/compositing/chunk_to_layer_mapper.h"

#include <optional>
#include <utility>

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/graphics/paint/display_item.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_chunk.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/testing/fake_display_item_client.h"
#include "third_party/blink/renderer/platform/testing/paint_property_test_helpers.h"

namespace blink {

class ChunkToLayerMapperTest : public testing::Test {
 protected:
  static PaintChunk Chunk(const PropertyTreeState& state) {
    DEFINE_STATIC_LOCAL(Persistent<FakeDisplayItemClient>, fake_client,
                        (MakeGarbageCollected<FakeDisplayItemClient>()));
    DEFINE_STATIC_LOCAL(
        std::optional<PaintChunk::Id>, id,
        (PaintChunk::Id(fake_client->Id(), DisplayItem::kDrawingFirst)));
    PaintChunk chunk(0, 1, *fake_client, *id, state);
    return chunk;
  }

  // A state containing arbitrary values which should not affect test results
  // if the state is used as a layer state.
  PropertyTreeState LayerState() {
    if (!layer_transform_) {
      layer_transform_ = CreateTransform(t0(), MakeTranslationMatrix(123, 456),
                                         gfx::Point3F(1, 2, 3));
      layer_clip_ =
          CreateClip(c0(), *layer_transform_, FloatRoundedRect(12, 34, 56, 78));
      layer_effect_ = EffectPaintPropertyNode::Create(
          e0(), EffectPaintPropertyNode::State{
                    layer_transform_, layer_clip_, CompositorFilterOperations(),
                    nullptr, 0.789f, SkBlendMode::kSrcIn});
    }
    return PropertyTreeState(*layer_transform_, *layer_clip_, *layer_effect_);
  }

  bool HasFilterThatMovesPixels(const ChunkToLayerMapper& mapper) {
    return mapper.has_filter_that_moves_pixels_;
  }

  Persistent<TransformPaintPropertyNode> layer_transform_;
  Persistent<ClipPaintPropertyNode> layer_clip_;
  Persistent<EffectPaintPropertyNode> layer_effect_;
};

TEST_F(ChunkToLayerMapperTest, OneChunkUsingLayerState) {
  ChunkToLayerMapper mapper(LayerState(), gfx::Vector2dF(10, 20));
  auto chunk = Chunk(LayerState());
  mapper.SwitchToChunk(chunk);
  EXPECT_FALSE(HasFilterThatMovesPixels(mapper));
  EXPECT_EQ(MakeTranslationMatrix(-10, -20), mapper.Transform());
  EXPECT_EQ(FloatClipRect(), mapper.ClipRect());
  EXPECT_EQ(gfx::Rect(20, 10, 88, 99),
            mapper.MapVisualRect(gfx::Rect(30, 30, 88, 99)));
  EXPECT_EQ(gfx::Rect(), mapper.MapVisualRect(gfx::Rect()));
}

TEST_F(ChunkToLayerMapperTest, TwoChunkUsingLayerState) {
  ChunkToLayerMapper mapper(LayerState(), gfx::Vector2dF(10, 20));
  auto chunk1 = Chunk(LayerState());
  auto chunk2 = Chunk(LayerState());

  mapper.SwitchToChunk(chunk1);
  EXPECT_FALSE(HasFilterThatMovesPixels(mapper));
  EXPECT_EQ(MakeTranslationMatrix(-10, -20), mapper.Transform());
  EXPECT_EQ(FloatClipRect(), mapper.ClipRect());
  EXPECT_EQ(gfx::Rect(20, 10, 88, 99),
            mapper.MapVisualRect(gfx::Rect(30, 30, 88, 99)));
  EXPECT_EQ(gfx::Rect(), mapper.MapVisualRect(gfx::Rect()));

  mapper.SwitchToChunk(chunk2);
  EXPECT_FALSE(HasFilterThatMovesPixels(mapper));
  EXPECT_EQ(MakeTranslationMatrix(-10, -20), mapper.Transform());
  EXPECT_EQ(FloatClipRect(), mapper.ClipRect());
  EXPECT_EQ(gfx::Rect(20, 10, 88, 99),
            mapper.MapVisualRect(gfx::Rect(30, 30, 88, 99)));
  EXPECT_EQ(gfx::Rect(), mapper.MapVisualRect(gfx::Rect()));
}

TEST_F(ChunkToLayerMapperTest, TwoChunkSameState) {
  ChunkToLayerMapper mapper(LayerState(), gfx::Vector2dF(10, 20));
  auto* transform =
      CreateTransform(LayerState().Transform(), MakeScaleMatrix(2));
  auto* clip = CreateClip(LayerState().Clip(), LayerState().Transform(),
                          FloatRoundedRect(10, 10, 100, 100));
  auto& effect = LayerState().Effect();
  auto chunk1 = Chunk(PropertyTreeState(*transform, *clip, effect));
  auto chunk2 = Chunk(PropertyTreeState(*transform, *clip, effect));

  mapper.SwitchToChunk(chunk1);
  EXPECT_FALSE(HasFilterThatMovesPixels(mapper));
  gfx::Transform expected_transform = MakeTranslationMatrix(-10, -20);
  expected_transform.Scale(2);
  EXPECT_EQ(expected_transform, mapper.Transform());
  EXPECT_EQ(gfx::RectF(0, -10, 100, 100), mapper.ClipRect().Rect());
  EXPECT_TRUE(mapper.ClipRect().IsTight());
  EXPECT_EQ(gfx::Rect(50, 40, 50, 50),
            mapper.MapVisualRect(gfx::Rect(30, 30, 88, 99)));
  EXPECT_EQ(gfx::Rect(), mapper.MapVisualRect(gfx::Rect()));

  mapper.SwitchToChunk(chunk2);
  EXPECT_FALSE(HasFilterThatMovesPixels(mapper));
  EXPECT_EQ(expected_transform, mapper.Transform());
  EXPECT_EQ(gfx::RectF(0, -10, 100, 100), mapper.ClipRect().Rect());
  EXPECT_TRUE(mapper.ClipRect().IsTight());
  EXPECT_EQ(gfx::Rect(50, 40, 50, 50),
            mapper.MapVisualRect(gfx::Rect(30, 30, 88, 99)));
  EXPECT_EQ(gfx::Rect(), mapper.MapVisualRect(gfx::Rect()));
}

TEST_F(ChunkToLayerMapperTest, TwoChunkDifferentState) {
  ChunkToLayerMapper mapper(LayerState(), gfx::Vector2dF(10, 20));
  auto* transform1 =
      CreateTransform(LayerState().Transform(), MakeScaleMatrix(2));
  auto* clip1 = CreateClip(LayerState().Clip(), LayerState().Transform(),
                           FloatRoundedRect(10, 10, 100, 100));
  auto& effect = LayerState().Effect();
  auto chunk1 = Chunk(PropertyTreeState(*transform1, *clip1, effect));

  auto* transform2 = Create2DTranslation(*transform1, 20, 30);
  auto* clip2 = CreateClip(LayerState().Clip(), *transform2,
                           FloatRoundedRect(0, 0, 20, 20));
  auto chunk2 = Chunk(PropertyTreeState(*transform2, *clip2, effect));

  mapper.SwitchToChunk(chunk1);
  EXPECT_FALSE(HasFilterThatMovesPixels(mapper));
  gfx::Transform expected_transform = MakeTranslationMatrix(-10, -20);
  expected_transform.Scale(2);
  EXPECT_EQ(expected_transform, mapper.Transform());
  EXPECT_EQ(gfx::RectF(0, -10, 100, 100), mapper.ClipRect().Rect());
  EXPECT_TRUE(mapper.ClipRect().IsTight());
  EXPECT_EQ(gfx::Rect(50, 40, 50, 50),
            mapper.MapVisualRect(gfx::Rect(30, 30, 88, 99)));
  EXPECT_EQ(gfx::Rect(), mapper.MapVisualRect(gfx::Rect()));

  mapper.SwitchToChunk(chunk2);
  EXPECT_FALSE(HasFilterThatMovesPixels(mapper));
  expected_transform.Translate(20, 30);
  EXPECT_EQ(expected_transform, mapper.Transform());
  EXPECT_EQ(gfx::RectF(30, 40, 40, 40), mapper.ClipRect().Rect());
  EXPECT_FALSE(mapper.ClipRect().IsTight());
  EXPECT_EQ(gfx::Rect(30, 40, 40, 40),
            mapper.MapVisualRect(gfx::Rect(0, 0, 200, 200)));
  EXPECT_EQ(gfx::Rect(), mapper.MapVisualRect(gfx::Rect()));
}

TEST_F(ChunkToLayerMapperTest, SlowPath) {
  ChunkToLayerMapper mapper(LayerState(), gfx::Vector2dF(10, 20));
  auto chunk1 = Chunk(LayerState());

  // Chunk2 has a blur filter. Should use the slow path.
  CompositorFilterOperations filter2;
  filter2.AppendBlurFilter(20);
  auto* effect2 = CreateFilterEffect(LayerState().Effect(), std::move(filter2));
  auto* clip_expander =
      CreatePixelMovingFilterClipExpander(LayerState().Clip(), *effect2);
  auto chunk2 = Chunk(
      PropertyTreeState(LayerState().Transform(), *clip_expander, *effect2));

  // Chunk3 has a different effect which inherits from chunk2's effect.
  // Should use the slow path.
  auto* effect3 = CreateOpacityEffect(*effect2, 1.f);
  auto chunk3 = Chunk(
      PropertyTreeState(LayerState().Transform(), *clip_expander, *effect3));

  // Chunk4 has an opacity filter effect which inherits from the layer's effect.
  // Should use the fast path.
  CompositorFilterOperations filter4;
  filter4.AppendOpacityFilter(0.5);
  auto* effect4 = CreateFilterEffect(LayerState().Effect(), std::move(filter4));
  auto chunk4 = Chunk(PropertyTreeState(LayerState().Transform(),
                                        LayerState().Clip(), *effect4));

  // Chunk5 goes back to the layer state.
  auto chunk5 = Chunk(LayerState());

  mapper.SwitchToChunk(chunk1);
  EXPECT_FALSE(HasFilterThatMovesPixels(mapper));
  EXPECT_EQ(MakeTranslationMatrix(-10, -20), mapper.Transform());
  EXPECT_EQ(FloatClipRect(), mapper.ClipRect());

  mapper.SwitchToChunk(chunk2);
  EXPECT_TRUE(HasFilterThatMovesPixels(mapper));
  EXPECT_EQ(MakeTranslationMatrix(-10, -20), mapper.Transform());
  EXPECT_TRUE(mapper.ClipRect().IsInfinite());
  EXPECT_EQ(gfx::Rect(-40, -50, 208, 219),
            mapper.MapVisualRect(gfx::Rect(30, 30, 88, 99)));
  EXPECT_EQ(gfx::Rect(), mapper.MapVisualRect(gfx::Rect()));

  mapper.SwitchToChunk(chunk3);
  EXPECT_TRUE(HasFilterThatMovesPixels(mapper));
  EXPECT_EQ(MakeTranslationMatrix(-10, -20), mapper.Transform());
  EXPECT_TRUE(mapper.ClipRect().IsInfinite());
  EXPECT_EQ(gfx::Rect(-40, -50, 208, 219),
            mapper.MapVisualRect(gfx::Rect(30, 30, 88, 99)));
  EXPECT_EQ(gfx::Rect(), mapper.MapVisualRect(gfx::Rect()));

  mapper.SwitchToChunk(chunk4);
  EXPECT_FALSE(HasFilterThatMovesPixels(mapper));
  EXPECT_EQ(MakeTranslationMatrix(-10, -20), mapper.Transform());
  EXPECT_EQ(FloatClipRect(), mapper.ClipRect());

  mapper.SwitchToChunk(chunk5);
  EXPECT_FALSE(HasFilterThatMovesPixels(mapper));
  EXPECT_EQ(MakeTranslationMatrix(-10, -20), mapper.Transform());
  EXPECT_EQ(FloatClipRect(), mapper.ClipRect());
}

TEST_F(ChunkToLayerMapperTest, SwitchToSiblingEffect) {
  auto* effect1 = CreateOpacityEffect(LayerState().Effect(), 0.5f);
  auto chunk1 = Chunk(PropertyTreeState(LayerState().Transform(),
                                        LayerState().Clip(), *effect1));
  auto* effect2 = CreateOpacityEffect(LayerState().Effect(), 0.5f);
  auto chunk2 = Chunk(PropertyTreeState(LayerState().Transform(),
                                        LayerState().Clip(), *effect2));

  ChunkToLayerMapper mapper(chunk1.properties.Unalias(),
                            gfx::Vector2dF(10, 20));
  mapper.SwitchToChunk(chunk2);
  EXPECT_FALSE(HasFilterThatMovesPixels(mapper));
}

}  // namespace blink
```