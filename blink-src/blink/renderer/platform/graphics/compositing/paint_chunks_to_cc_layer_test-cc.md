Response:
The user wants me to analyze a C++ source code file from the Chromium Blink rendering engine.
Specifically, they want me to:
1. **Summarize the file's functionality.**
2. **Explain its relationship to web technologies (JavaScript, HTML, CSS).**  I need to provide concrete examples if such a relationship exists.
3. **Demonstrate logical reasoning with input/output examples.** This likely involves understanding how the code transforms data.
4. **Highlight common usage errors, both for users and programmers.**
5. **Focus on the provided first part of the file.**

Let's break down the code:

- **Headers:** The included headers suggest this file is related to:
    - **`paint_chunks_to_cc_layer.h`**:  Likely the core functionality being tested. It probably converts paint chunks into `cc::Layer` structures.
    - **`cc/layers/layer.h`**:  Interaction with Chromium's Compositor (cc) layer system.
    - **`cc/paint/...`**:  Working with Chromium's Paint system, including display item lists, paint filters, paint flags, and operation buffers.
    - **`testing/gmock/gmock.h` and `testing/gtest/gtest.h`**:  Indicates this is a unit test file using Google Test and Google Mock.
    - **`third_party/blink/renderer/platform/graphics/paint/...`**:  Blink's specific paint-related data structures like `PaintChunk`, `PaintChunkSubset`, and property nodes (`ClipPaintPropertyNode`, `EffectPaintPropertyNode`, `TransformPaintPropertyNode`).
    - **`third_party/blink/renderer/platform/heap/persistent.h`**: Memory management within Blink.
    - **`third_party/blink/renderer/platform/testing/...`**:  Blink's testing utilities.
    - **`ui/gfx/geometry/skia_conversions.h`**:  Converting between gfx geometry and Skia's geometry types.

- **Namespaces:** The code operates within the `blink` and anonymous namespaces.

- **Helper Functions/Classes:**
    - `MakeRegionCaptureData`: Creates a `RegionCaptureData` object, suggesting handling of screen capture regions.
    - `PaintChunksToCcLayerTest`:  The main test fixture, inheriting from `testing::Test` and `PaintTestConfigurations`.
    - `DefaultClient`:  Provides a default `FakeDisplayItemClient` for testing.
    - `DefaultId`: Generates a default `PaintChunk::Id`.
    - `UpdateLayerProperties`: Updates properties of a `cc::Layer` based on `PaintChunkSubset` information.
    - `TestChunks`: A helper class to create and manage `PaintChunk` data for testing purposes. It allows adding chunks with different properties and paint records.

- **Tests:**  The code contains a series of test cases using the `TEST_P` macro (parameterized tests). These tests seem to verify the correct conversion of different combinations of paint chunks and property nodes into `cc::PaintRecord` objects. The tests cover scenarios involving:
    - Effect grouping (opacity, filters)
    - Nested effects
    - Interleaved clips and effects
    - Clip space and effect space inversions
    - Non-root layers
    - Effects without output clips
    - Visual rect calculation
    - Non-composited clip paths
    - Empty and non-empty clips
    - Combining clips

**Overall Functionality (Part 1):**

Based on the code and the test names, this file is primarily focused on **unit testing the `PaintChunksToCcLayer` functionality**. `PaintChunksToCcLayer` is responsible for converting a set of `PaintChunk` objects (which represent portions of the rendering tree with associated drawing instructions and property information) into a `cc::PaintRecord`. This `cc::PaintRecord` can then be used by Chromium's Compositor to efficiently render content within a `cc::Layer`. The tests cover various scenarios of how different paint properties (transforms, clips, effects like opacity and filters) are handled during this conversion process.

这是 `blink/renderer/platform/graphics/compositing/paint_chunks_to_cc_layer_test.cc` 文件的第一部分，其主要功能是 **测试 `PaintChunksToCcLayer` 类的功能**。 `PaintChunksToCcLayer` 类负责将 Blink 渲染引擎中的 `PaintChunk` 对象转换为 Chromium Compositor (cc) 图层可以理解和使用的 `cc::PaintRecord`。

以下是对其功能的详细归纳：

1. **测试核心转换逻辑:**  这个文件的主要目的是验证 `PaintChunksToCcLayer::Convert` 方法的正确性。这个方法接收一个 `PaintChunkSubset` 对象（包含多个 `PaintChunk`），并根据这些 PaintChunk 的属性（例如变换、裁剪、特效等）生成一个 `cc::PaintRecord`。

2. **模拟和创建测试数据:**  文件中定义了 `TestChunks` 类，这是一个辅助类，用于方便地创建和管理用于测试的 `PaintChunk` 数据。它可以添加具有不同属性节点（Transform, Clip, Effect）和绘制指令的 `PaintChunk`。

3. **覆盖多种渲染场景:**  通过一系列的 `TEST_P` 测试用例，该文件覆盖了各种复杂的渲染场景，包括：
    * **特效分组 (Effect Grouping):**  测试具有相同特效的多个 PaintChunk 是否被正确地组合成一个 `SaveLayer` 操作。例如，多个透明度相同的元素是否被包裹在一个 `SaveLayerAlphaOp` 中。
    * **嵌套特效 (Effect Grouping Nested):** 测试嵌套的特效是否按照正确的顺序应用。
    * **带变换的嵌套特效 (EffectFilterGroupingNestedWithTransforms):** 测试在存在变换的情况下，嵌套特效是否正确处理。
    * **交错的裁剪和特效 (InterleavedClipEffect):**  测试裁剪和特效交替出现时的处理逻辑，验证特效是否被其对应的输出裁剪正确包围。
    * **裁剪空间反转 (ClipSpaceInversion):**  测试当 PaintChunk 的变换状态比其裁剪属性的变换状态更浅时，是否能正确渲染。这对应于 CSS 中的 `position: absolute; clip: rect(...)` 和 `position: fixed;` 的场景。
    * **特效空间反转 (OpacityEffectSpaceInversion, FilterEffectSpaceInversion):** 测试当 PaintChunk 的变换状态比其特效属性的变换状态更浅时，是否能正确渲染。这对应于 CSS 中滚动容器内的固定定位透明/滤镜元素。
    * **非根图层 (NonRootLayerSimple, NonRootLayerTransformEscape):** 测试当目标图层本身具有复合属性时，`PaintChunksToCcLayer` 的行为。
    * **没有输出裁剪的特效 (EffectWithNoOutputClip, EffectWithNoOutputClipNestedInDecompositedEffect 等):**  测试当特效没有明确的输出裁剪时，如何处理。
    * **可视区域 (VisualRect):**  测试计算由 PaintChunk 生成的绘制操作的可视区域。
    * **非复合裁剪路径 (NoncompositedClipPath):** 测试包含裁剪路径的 PaintChunk 的处理。
    * **空裁剪的优化 (EmptyClipsAreElided):** 测试对于没有绘制内容的 PaintChunk，其相关的裁剪操作是否可以被优化掉。
    * **非空裁剪的处理 (NonEmptyClipsAreStored):** 测试对于包含绘制内容的 PaintChunk，其裁剪操作是否被正确保留。
    * **空特效的处理 (EmptyEffectsAreStored):** 测试对于没有实际效果的特效，是否需要生成相应的操作。
    * **合并裁剪 (CombineClips, CombineClipsAcrossTransform, CombineClipsWithRoundedRects):** 测试如何合并相邻的裁剪属性，以减少绘制操作的数量。涵盖了不同类型的裁剪（矩形、圆角矩形、裁剪路径）和变换的情况。

4. **使用 Google Test 和 Google Mock:**  该文件使用了 Google Test 框架进行单元测试，并可能使用了 Google Mock 来模拟依赖项（虽然在这个片段中没有明显的 Mock 用例）。

**与 JavaScript, HTML, CSS 的关系举例：**

`PaintChunksToCcLayer` 的功能直接关系到浏览器如何将 HTML、CSS 样式渲染到屏幕上。

* **CSS 样式和特效:** CSS 的 `opacity` 属性会被转换为 `EffectPaintPropertyNode`，并在 `PaintChunksToCcLayer` 中被转换为 `cc::SaveLayerAlphaOp` 操作。例如，如果一个 HTML 元素的 CSS 样式是 `opacity: 0.5;`，那么对应的 `PaintChunk` 会包含一个 opacity 为 0.5 的 `EffectPaintPropertyNode`，测试用例 `EffectGroupingSimple` 就是在验证这种情况。

* **CSS 裁剪:** CSS 的 `clip` 或 `clip-path` 属性会被转换为 `ClipPaintPropertyNode`，并在 `PaintChunksToCcLayer` 中被转换为 `cc::ClipRectOp` 或 `cc::ClipPathOp` 操作。例如，一个设置了 `clip: rect(10px, 20px, 30px, 40px);` 的 HTML 元素，其对应的 `PaintChunk` 会包含一个定义了该裁剪区域的 `ClipPaintPropertyNode`，测试用例 `InterleavedClipEffect` 和 `ClipSpaceInversion` 等都在测试裁剪相关的转换。

* **CSS 变换:** CSS 的 `transform` 属性会被转换为 `TransformPaintPropertyNode`，并在 `PaintChunksToCcLayer` 中被转换为 `cc::ConcatOp` 操作。例如，一个设置了 `transform: scale(2);` 的 HTML 元素，其对应的 `PaintChunk` 会包含一个缩放变换的 `TransformPaintPropertyNode`，测试用例 `EffectFilterGroupingNestedWithTransforms` 和 `OpacityEffectSpaceInversion` 等都涉及变换的处理。

* **HTML 结构和分层:** HTML 的 DOM 结构和 CSS 的分层上下文决定了 `PaintChunk` 的生成和属性继承。`PaintChunksToCcLayer` 的目标是将这些分散的 `PaintChunk` 转换成可以在 cc 图层上高效绘制的指令序列。

**假设输入与输出（逻辑推理）：**

**假设输入:** 一个 `TestChunks` 对象，其中添加了两个 `PaintChunk`，它们都应用了 `opacity: 0.5` 的特效。

```c++
auto* e1 = CreateOpacityEffect(e0(), 0.5f);
TestChunks chunks;
chunks.AddChunk(t0(), c0(), *e1, gfx::Rect(0, 0, 50, 50));
chunks.AddChunk(t0(), c0(), *e1, gfx::Rect(20, 20, 70, 70));
PaintChunkSubset subset = chunks.Build();
PropertyTreeState root_state = PropertyTreeState::Root();
```

**预期输出:** `PaintChunksToCcLayer::Convert(subset, root_state)` 应该返回一个 `cc::PaintRecord`，其包含以下操作（大致顺序）：

```
cc::SaveLayerAlphaOp(SkRect::MakeXYWH(0, 0, 90, 90), 0.5f); // 合并了两个 chunk 的 bounds
cc::DrawRecordOp(); // 第一个 chunk 的绘制指令
cc::DrawRecordOp(); // 第二个 chunk 的绘制指令
cc::RestoreOp();
```

**用户或编程常见的使用错误举例:**

虽然这个文件是测试代码，但可以推断出 `PaintChunksToCcLayer` 的使用者（Blink 渲染引擎的其他部分）可能会犯以下错误：

* **未能正确构建 `PaintChunkSubset`:** 如果传递给 `PaintChunksToCcLayer::Convert` 的 `PaintChunkSubset` 数据不正确（例如，`PaintChunk` 的属性节点关联错误），会导致渲染错误或崩溃。
* **假设 `PaintChunksToCcLayer` 处理所有可能的属性组合:**  开发者可能错误地假设 `PaintChunksToCcLayer` 能够处理所有 CSS 属性和特效的组合。实际上，某些复杂的属性可能需要特殊的处理或根本不被支持。
* **性能问题:**  如果生成了过多的或者不必要的绘制操作，可能会导致渲染性能下降。`PaintChunksToCcLayer` 的优化目标之一就是减少不必要的图层和绘制调用。

总而言之，`blink/renderer/platform/graphics/compositing/paint_chunks_to_cc_layer_test.cc` 的第一部分专注于测试将 Blink 渲染流水线中的中间表示 `PaintChunk` 转换为 Chromium Compositor 可以使用的绘制指令 `cc::PaintRecord` 的核心逻辑，并且覆盖了多种与 CSS 属性密切相关的渲染场景。

Prompt: 
```
这是目录为blink/renderer/platform/graphics/compositing/paint_chunks_to_cc_layer_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/graphics/compositing/paint_chunks_to_cc_layer.h"

#include <initializer_list>

#include "cc/layers/layer.h"
#include "cc/paint/display_item_list.h"
#include "cc/paint/paint_filter.h"
#include "cc/paint/paint_flags.h"
#include "cc/paint/paint_op_buffer_iterator.h"
#include "cc/paint/render_surface_filters.h"
#include "cc/test/paint_op_matchers.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/graphics/paint/clip_paint_property_node.h"
#include "third_party/blink/renderer/platform/graphics/paint/display_item_list.h"
#include "third_party/blink/renderer/platform/graphics/paint/drawing_display_item.h"
#include "third_party/blink/renderer/platform/graphics/paint/effect_paint_property_node.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_chunk.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_chunk_subset.h"
#include "third_party/blink/renderer/platform/graphics/paint/transform_paint_property_node.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/testing/fake_display_item_client.h"
#include "third_party/blink/renderer/platform/testing/paint_property_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/paint_test_configurations.h"
#include "ui/gfx/geometry/skia_conversions.h"

namespace blink {
namespace {

using ::cc::PaintOpEq;
using ::cc::PaintOpIs;
using ::testing::ElementsAre;

RegionCaptureData* MakeRegionCaptureData(
    std::initializer_list<std::pair<RegionCaptureCropId, gfx::Rect>>
        map_values) {
  RegionCaptureData* result = MakeGarbageCollected<RegionCaptureData>();
  result->map = map_values;
  return result;
}

class PaintChunksToCcLayerTest : public testing::Test,
                                 public PaintTestConfigurations {};

INSTANTIATE_PAINT_TEST_SUITE_P(PaintChunksToCcLayerTest);

const DisplayItemClient& DefaultClient() {
  DEFINE_STATIC_LOCAL(
      Persistent<FakeDisplayItemClient>, fake_client,
      (MakeGarbageCollected<FakeDisplayItemClient>("FakeDisplayItemClient")));
  return *fake_client;
}

PaintChunk::Id DefaultId() {
  return PaintChunk::Id(DefaultClient().Id(), DisplayItem::kDrawingFirst);
}

void UpdateLayerProperties(cc::Layer& layer,
                           const PropertyTreeState& layer_state,
                           const PaintChunkSubset& chunks) {
  cc::LayerSelection layer_selection;
  PaintChunksToCcLayer::UpdateLayerProperties(
      layer, layer_state, chunks, layer_selection, /*selection_only=*/false);
}

class TestChunks {
 public:
  // Add a paint chunk with a non-empty paint record and given property nodes.
  void AddChunk(
      const TransformPaintPropertyNodeOrAlias& t,
      const ClipPaintPropertyNodeOrAlias& c,
      const EffectPaintPropertyNodeOrAlias& e,
      const gfx::Rect& bounds = gfx::Rect(0, 0, 100, 100),
      const std::optional<gfx::Rect>& drawable_bounds = std::nullopt) {
    AddChunk(PropertyTreeStateOrAlias(t, c, e), bounds, drawable_bounds);
  }
  void AddChunk(
      const PropertyTreeStateOrAlias& state,
      const gfx::Rect& bounds = gfx::Rect(0, 0, 100, 100),
      const std::optional<gfx::Rect>& drawable_bounds = std::nullopt) {
    cc::PaintOpBuffer buffer;
    buffer.push<cc::DrawRectOp>(
        gfx::RectToSkRect(drawable_bounds.value_or(bounds)), cc::PaintFlags());
    AddChunk(buffer.ReleaseAsRecord(), state, bounds, drawable_bounds);
  }

  // Add a paint chunk with a given paint record and property nodes.
  void AddChunk(
      PaintRecord record,
      const TransformPaintPropertyNodeOrAlias& t,
      const ClipPaintPropertyNodeOrAlias& c,
      const EffectPaintPropertyNodeOrAlias& e,
      const gfx::Rect& bounds = gfx::Rect(0, 0, 100, 100),
      const std::optional<gfx::Rect>& drawable_bounds = std::nullopt) {
    AddChunk(record, PropertyTreeStateOrAlias(t, c, e), bounds,
             drawable_bounds);
  }
  void AddChunk(
      PaintRecord record,
      const PropertyTreeStateOrAlias& state,
      const gfx::Rect& bounds = gfx::Rect(0, 0, 100, 100),
      const std::optional<gfx::Rect>& drawable_bounds = std::nullopt) {
    auto& items = paint_artifact_->GetDisplayItemList();
    auto i = items.size();
    items.AllocateAndConstruct<DrawingDisplayItem>(
        DefaultId().client_id, DefaultId().type,
        drawable_bounds ? *drawable_bounds : bounds, std::move(record),
        RasterEffectOutset::kNone);

    auto& chunks = paint_artifact_->GetPaintChunks();
    chunks.emplace_back(i, i + 1, DefaultClient(), DefaultId(), state);
    chunks.back().bounds = bounds;
    chunks.back().drawable_bounds = drawable_bounds ? *drawable_bounds : bounds;
  }

  void AddEmptyChunk(const TransformPaintPropertyNodeOrAlias& t,
                     const ClipPaintPropertyNodeOrAlias& c,
                     const EffectPaintPropertyNodeOrAlias& e,
                     const gfx::Rect& bounds = gfx::Rect(0, 0, 100, 100)) {
    AddEmptyChunk(PropertyTreeStateOrAlias(t, c, e), bounds);
  }
  void AddEmptyChunk(const PropertyTreeStateOrAlias& state,
                     const gfx::Rect& bounds = gfx::Rect(0, 0, 100, 100)) {
    auto& chunks = paint_artifact_->GetPaintChunks();
    auto i = paint_artifact_->GetDisplayItemList().size();
    chunks.emplace_back(i, i, DefaultClient(), DefaultId(), state);
    chunks.back().bounds = bounds;
  }

  PaintChunks& GetChunks() { return paint_artifact_->GetPaintChunks(); }

  PaintChunkSubset Build() { return PaintChunkSubset(*paint_artifact_); }

 private:
  Persistent<PaintArtifact> paint_artifact_ =
      MakeGarbageCollected<PaintArtifact>();
};

TEST_P(PaintChunksToCcLayerTest, EffectGroupingSimple) {
  // This test verifies effects are applied as a group.
  auto* e1 = CreateOpacityEffect(e0(), 0.5f);
  TestChunks chunks;
  chunks.AddChunk(t0(), c0(), *e1, gfx::Rect(0, 0, 50, 50));
  chunks.AddChunk(t0(), c0(), *e1, gfx::Rect(20, 20, 70, 70));

  PaintRecord output =
      PaintChunksToCcLayer::Convert(chunks.Build(), PropertyTreeState::Root());
  EXPECT_THAT(output, ElementsAre(PaintOpEq<cc::SaveLayerAlphaOp>(
                                      SkRect::MakeXYWH(0, 0, 90, 90),
                                      0.5f),                      // <e1>
                                  PaintOpIs<cc::DrawRecordOp>(),  // <p0/>
                                  PaintOpIs<cc::DrawRecordOp>(),  // <p1/>
                                  PaintOpIs<cc::RestoreOp>()));   // </e1>
}

TEST_P(PaintChunksToCcLayerTest, EffectGroupingNested) {
  // This test verifies nested effects are grouped properly.
  auto* e1 = CreateOpacityEffect(e0(), 0.5f);
  auto* e2 = CreateOpacityEffect(*e1, 0.5f);
  auto* e3 = CreateOpacityEffect(*e1, 0.5f);
  TestChunks chunks;
  chunks.AddChunk(t0(), c0(), *e2);
  chunks.AddChunk(t0(), c0(), *e3, gfx::Rect(111, 222, 333, 444));

  PaintRecord output =
      PaintChunksToCcLayer::Convert(chunks.Build(), PropertyTreeState::Root());
  EXPECT_THAT(
      output,
      ElementsAre(
          PaintOpEq<cc::SaveLayerAlphaOp>(SkRect::MakeXYWH(0, 0, 444, 666),
                                          0.5f),  // <e1>
          PaintOpEq<cc::SaveLayerAlphaOp>(SkRect::MakeXYWH(0, 0, 100, 100),
                                          0.5f),  // <e2>
          PaintOpIs<cc::DrawRecordOp>(),          // <p0/>
          PaintOpIs<cc::RestoreOp>(),             // </e2>
          PaintOpEq<cc::SaveLayerAlphaOp>(SkRect::MakeXYWH(111, 222, 333, 444),
                                          0.5f),  // <e3>
          PaintOpIs<cc::DrawRecordOp>(),          // <p1/>
          PaintOpIs<cc::RestoreOp>(),             // </e3>
          PaintOpIs<cc::RestoreOp>()));           // </e1>
}

TEST_P(PaintChunksToCcLayerTest, EffectFilterGroupingNestedWithTransforms) {
  // This test verifies nested effects with transforms are grouped properly.
  auto* t1 = CreateTransform(t0(), MakeScaleMatrix(2));
  auto* t2 = Create2DTranslation(*t1, -50, -50);
  auto* e1 = CreateOpacityEffect(e0(), *t2, &c0(), 0.5);

  CompositorFilterOperations filter;
  filter.AppendBlurFilter(5);
  auto* e2 = CreateFilterEffect(*e1, filter);
  TestChunks chunks;
  chunks.AddChunk(*t2, c0(), *e1, gfx::Rect(0, 0, 50, 50));
  chunks.AddChunk(*t1, c0(), *e2, gfx::Rect(20, 20, 70, 70));

  PaintRecord output =
      PaintChunksToCcLayer::Convert(chunks.Build(), PropertyTreeState::Root());

  cc::PaintFlags expected_flags;
  expected_flags.setImageFilter(cc::RenderSurfaceFilters::BuildImageFilter(
      filter.AsCcFilterOperations()));
  EXPECT_THAT(
      output,
      ElementsAre(
          PaintOpIs<cc::SaveOp>(),
          PaintOpEq<cc::ConcatOp>(
              gfx::TransformToSkM44(t1->Matrix() * t2->Matrix())),  // <t1*t2>
          // chunk1.bounds + e2(t2^-1(chunk2.bounds))
          PaintOpEq<cc::SaveLayerAlphaOp>(SkRect::MakeXYWH(0, 0, 155, 155),
                                          0.5f),  // <e1>
          PaintOpIs<cc::DrawRecordOp>(),          // <p1/>
          // t2^-1(chunk2.bounds)
          PaintOpEq<cc::SaveLayerOp>(SkRect::MakeXYWH(70, 70, 70, 70),
                                     expected_flags),  // <e2>
          PaintOpIs<cc::SaveOp>(),
          // t2^1
          PaintOpEq<cc::TranslateOp>(-t2->Get2dTranslation().x(),
                                     -t2->Get2dTranslation().y()),  // <t2^-1>
          PaintOpIs<cc::DrawRecordOp>(),                            // <p2/>
          PaintOpIs<cc::RestoreOp>(),                               // </t2^-1>
          PaintOpIs<cc::RestoreOp>(),                               // </e2>
          PaintOpIs<cc::RestoreOp>(),                               // </e1>
          PaintOpIs<cc::RestoreOp>()));                             // </t1*t2>
}

TEST_P(PaintChunksToCcLayerTest, InterleavedClipEffect) {
  // This test verifies effects are enclosed by their output clips.
  // It is the same as the example made in the class comments of
  // ConversionContext.
  // Refer to PaintChunksToCcLayer.cpp for detailed explanation.
  // (Search "State management example".)
  auto* c1 = CreateClip(c0(), t0(), FloatRoundedRect(0.f, 0.f, 1.f, 1.f));
  auto* c2 = CreateClip(*c1, t0(), FloatRoundedRect(0.f, 0.f, 1.f, 1.f));
  auto* c3 = CreateClip(*c2, t0(), FloatRoundedRect(0.f, 0.f, 1.f, 1.f));
  auto* c4 = CreateClip(*c3, t0(), FloatRoundedRect(0.f, 0.f, 1.f, 1.f));
  auto* e1 = CreateOpacityEffect(e0(), t0(), c2, 0.5);
  auto* e2 = CreateOpacityEffect(*e1, t0(), c4, 0.5);
  TestChunks chunks;
  chunks.AddChunk(t0(), *c2, e0());
  chunks.AddChunk(t0(), *c3, e0());
  chunks.AddChunk(t0(), *c4, *e2, gfx::Rect(0, 0, 50, 50));
  chunks.AddChunk(t0(), *c3, *e1, gfx::Rect(20, 20, 70, 70));
  chunks.AddChunk(t0(), *c4, e0());

  PaintRecord output =
      PaintChunksToCcLayer::Convert(chunks.Build(), PropertyTreeState::Root());
  EXPECT_THAT(
      output,
      ElementsAre(
          PaintOpIs<cc::SaveOp>(),
          PaintOpIs<cc::ClipRectOp>(),    // <c1+c2>
          PaintOpIs<cc::DrawRecordOp>(),  // <p0/>
          PaintOpIs<cc::SaveOp>(),
          PaintOpIs<cc::ClipRectOp>(),    // <c3>
          PaintOpIs<cc::DrawRecordOp>(),  // <p1/>
          PaintOpIs<cc::RestoreOp>(),     // </c3>
          PaintOpEq<cc::SaveLayerAlphaOp>(SkRect::MakeXYWH(0, 0, 90, 90),
                                          0.5f),  // <e1>
          PaintOpIs<cc::SaveOp>(),
          PaintOpIs<cc::ClipRectOp>(),  // <c3+c4>
          PaintOpEq<cc::SaveLayerAlphaOp>(SkRect::MakeXYWH(0, 0, 50, 50),
                                          0.5f),  // <e2>
          PaintOpIs<cc::DrawRecordOp>(),          // <p2/>
          PaintOpIs<cc::RestoreOp>(),             // </e2>
          PaintOpIs<cc::RestoreOp>(),             // </c3+c4>
          PaintOpIs<cc::SaveOp>(),
          PaintOpIs<cc::ClipRectOp>(),    // <c3>
          PaintOpIs<cc::DrawRecordOp>(),  // <p3/>
          PaintOpIs<cc::RestoreOp>(),     // </c3>
          PaintOpIs<cc::RestoreOp>(),     // </e1>
          PaintOpIs<cc::SaveOp>(),
          PaintOpIs<cc::ClipRectOp>(),    // <c3+c4>
          PaintOpIs<cc::DrawRecordOp>(),  // <p4/>
          PaintOpIs<cc::RestoreOp>(),     // </c3+c4>
          PaintOpIs<cc::RestoreOp>()));   // </c1+c2>
}

TEST_P(PaintChunksToCcLayerTest, ClipSpaceInversion) {
  // This test verifies chunks that have a shallower transform state than
  // its clip can still be painted. The infamous CSS corner case:
  // <div style="position:absolute; clip:rect(...)">
  //     <div style="position:fixed;">Clipped but not scroll along.</div>
  // </div>
  auto* t1 = CreateTransform(t0(), MakeScaleMatrix(2));
  auto* c1 = CreateClip(c0(), *t1, FloatRoundedRect(0.f, 0.f, 1.f, 1.f));
  TestChunks chunks;
  chunks.AddChunk(t0(), *c1, e0());

  PaintRecord output =
      PaintChunksToCcLayer::Convert(chunks.Build(), PropertyTreeState::Root());
  EXPECT_THAT(output, ElementsAre(PaintOpIs<cc::SaveOp>(),
                                  PaintOpIs<cc::ConcatOp>(),    // <t1
                                  PaintOpIs<cc::ClipRectOp>(),  //  c1>
                                  PaintOpIs<cc::SaveOp>(),
                                  PaintOpIs<cc::ConcatOp>(),      // <t1^-1>
                                  PaintOpIs<cc::DrawRecordOp>(),  // <p0/>
                                  PaintOpIs<cc::RestoreOp>(),     // </t1^-1>
                                  PaintOpIs<cc::RestoreOp>()));   // </c1 t1>
}

TEST_P(PaintChunksToCcLayerTest, OpacityEffectSpaceInversion) {
  // This test verifies chunks that have a shallower transform state than
  // its effect can still be painted. The infamous CSS corner case:
  // <div style="overflow:scroll">
  //   <div style="opacity:0.5">
  //     <div style="position:absolute;">Transparent but not scroll along.</div>
  //   </div>
  // </div>
  auto* t1 = CreateTransform(t0(), MakeScaleMatrix(2));
  auto* e1 = CreateOpacityEffect(e0(), *t1, &c0(), 0.5);
  TestChunks chunks;
  chunks.AddChunk(t0(), c0(), *e1);
  chunks.AddChunk(*t1, c0(), *e1);

  PaintRecord output =
      PaintChunksToCcLayer::Convert(chunks.Build(), PropertyTreeState::Root());
  EXPECT_THAT(
      output,
      ElementsAre(
          PaintOpIs<cc::SaveOp>(),
          PaintOpEq<cc::ConcatOp>(gfx::TransformToSkM44(t1->Matrix())),  // <t1>
          PaintOpEq<cc::SaveLayerAlphaOp>(SkRect::MakeXYWH(0, 0, 100, 100),
                                          0.5f),  // <e1>
          PaintOpIs<cc::SaveOp>(),
          PaintOpEq<cc::ConcatOp>(gfx::TransformToSkM44(
              t1->Matrix().GetCheckedInverse())),  // <t1^-1>
          PaintOpIs<cc::DrawRecordOp>(),           // <p0/>
          PaintOpIs<cc::RestoreOp>(),              // </t1^-1>
          PaintOpIs<cc::DrawRecordOp>(),           // <p1/>
          PaintOpIs<cc::RestoreOp>(),              // </e1>
          PaintOpIs<cc::RestoreOp>()));            // </t1>
}

TEST_P(PaintChunksToCcLayerTest, FilterEffectSpaceInversion) {
  // This test verifies chunks that have a shallower transform state than
  // its effect can still be painted. The infamous CSS corner case:
  // <div style="overflow:scroll">
  //   <div style="filter:blur(1px)">
  //     <div style="position:absolute;">Filtered but not scroll along.</div>
  //   </div>
  // </div>
  auto* t1 = CreateTransform(t0(), MakeScaleMatrix(2));
  CompositorFilterOperations filter;
  filter.AppendBlurFilter(5);
  auto* e1 = CreateFilterEffect(e0(), *t1, &c0(), filter);
  TestChunks chunks;
  chunks.AddChunk(t0(), c0(), *e1);

  auto output =
      PaintChunksToCcLayer::Convert(chunks.Build(), PropertyTreeState::Root());

  cc::PaintFlags expected_flags;
  expected_flags.setImageFilter(cc::RenderSurfaceFilters::BuildImageFilter(
      filter.AsCcFilterOperations()));
  EXPECT_THAT(
      output,
      ElementsAre(
          PaintOpIs<cc::SaveOp>(),
          PaintOpEq<cc::ConcatOp>(gfx::TransformToSkM44(t1->Matrix())),  // <t1>
          PaintOpEq<cc::SaveLayerOp>(SkRect::MakeXYWH(0, 0, 50, 50),
                                     expected_flags),  // <e1>
          PaintOpIs<cc::SaveOp>(),
          PaintOpEq<cc::ConcatOp>(gfx::TransformToSkM44(
              t1->Matrix().GetCheckedInverse())),  // <t1^-1>
          PaintOpIs<cc::DrawRecordOp>(),           // <p0/>
          PaintOpIs<cc::RestoreOp>(),              // </t1^-1>
          PaintOpIs<cc::RestoreOp>(),              // </e1>
          PaintOpIs<cc::RestoreOp>()));            // </t1>
}

TEST_P(PaintChunksToCcLayerTest, NonRootLayerSimple) {
  // This test verifies a layer with composited property state does not
  // apply properties again internally.
  auto* t1 = CreateTransform(t0(), MakeScaleMatrix(2));
  auto* c1 = CreateClip(c0(), t0(), FloatRoundedRect(0.f, 0.f, 1.f, 1.f));
  auto* e1 = CreateOpacityEffect(e0(), 0.5f);
  TestChunks chunks;
  chunks.AddChunk(*t1, *c1, *e1);

  PaintRecord output = PaintChunksToCcLayer::Convert(
      chunks.Build(), PropertyTreeState(*t1, *c1, *e1));
  EXPECT_THAT(output, ElementsAre(PaintOpIs<cc::DrawRecordOp>()));
}

TEST_P(PaintChunksToCcLayerTest, NonRootLayerTransformEscape) {
  // This test verifies chunks that have a shallower transform state than the
  // layer can still be painted.
  auto* t1 = CreateTransform(t0(), MakeScaleMatrix(2));
  auto* c1 = CreateClip(c0(), t0(), FloatRoundedRect(0.f, 0.f, 1.f, 1.f));
  auto* e1 = CreateOpacityEffect(e0(), 0.5f);
  TestChunks chunks;
  chunks.AddChunk(t0(), *c1, *e1);

  PaintRecord output = PaintChunksToCcLayer::Convert(
      chunks.Build(), PropertyTreeState(*t1, *c1, *e1));
  EXPECT_THAT(output, ElementsAre(PaintOpIs<cc::SaveOp>(),
                                  PaintOpIs<cc::ConcatOp>(),      // <t1^-1>
                                  PaintOpIs<cc::DrawRecordOp>(),  // <p0/>
                                  PaintOpIs<cc::RestoreOp>()));   // </t1^-1>
}

TEST_P(PaintChunksToCcLayerTest, EffectWithNoOutputClip) {
  // This test verifies effect with no output clip can be correctly processed.
  auto* c1 = CreateClip(c0(), t0(), FloatRoundedRect(0.f, 0.f, 1.f, 1.f));
  auto* c2 = CreateClip(*c1, t0(), FloatRoundedRect(0.f, 0.f, 1.f, 1.f));
  auto* e1 = CreateOpacityEffect(e0(), t0(), nullptr, 0.5);

  TestChunks chunks;
  chunks.AddChunk(t0(), *c2, *e1);

  PaintRecord output = PaintChunksToCcLayer::Convert(
      chunks.Build(), PropertyTreeState(t0(), *c1, e0()));
  EXPECT_THAT(output, ElementsAre(PaintOpEq<cc::SaveLayerAlphaOp>(
                                      SkRect::MakeXYWH(0, 0, 100, 100),
                                      0.5f),  // <e1>
                                  PaintOpIs<cc::SaveOp>(),
                                  PaintOpIs<cc::ClipRectOp>(),    // <c2>
                                  PaintOpIs<cc::DrawRecordOp>(),  // <p0/>
                                  PaintOpIs<cc::RestoreOp>(),     // </c2>
                                  PaintOpIs<cc::RestoreOp>()));   // </e1>
}

TEST_P(PaintChunksToCcLayerTest,
       EffectWithNoOutputClipNestedInDecompositedEffect) {
  auto* c1 = CreateClip(c0(), t0(), FloatRoundedRect(0.f, 0.f, 1.f, 1.f));
  auto* e1 = CreateOpacityEffect(e0(), 0.5);
  auto* e2 = CreateOpacityEffect(*e1, t0(), nullptr, 0.5);

  TestChunks chunks;
  chunks.AddChunk(t0(), *c1, *e2);

  PaintRecord output =
      PaintChunksToCcLayer::Convert(chunks.Build(), PropertyTreeState::Root());
  EXPECT_THAT(
      output,
      ElementsAre(
          PaintOpEq<cc::SaveLayerAlphaOp>(SkRect::MakeXYWH(0, 0, 100, 100),
                                          0.5f),  // <e1>
          PaintOpEq<cc::SaveLayerAlphaOp>(SkRect::MakeXYWH(0, 0, 100, 100),
                                          0.5f),  // <e2>
          PaintOpIs<cc::SaveOp>(),
          PaintOpIs<cc::ClipRectOp>(),    // <c1>
          PaintOpIs<cc::DrawRecordOp>(),  // <p0/>
          PaintOpIs<cc::RestoreOp>(),     // </c1>
          PaintOpIs<cc::RestoreOp>(),     // </e2>
          PaintOpIs<cc::RestoreOp>()));   // </e1>
}

TEST_P(PaintChunksToCcLayerTest,
       EffectWithNoOutputClipNestedInCompositedEffect) {
  auto* c1 = CreateClip(c0(), t0(), FloatRoundedRect(0.f, 0.f, 1.f, 1.f));
  auto* e1 = CreateOpacityEffect(e0(), 0.5);
  auto* e2 = CreateOpacityEffect(*e1, t0(), nullptr, 0.5);

  TestChunks chunks;
  chunks.AddChunk(t0(), *c1, *e2);

  PaintRecord output = PaintChunksToCcLayer::Convert(
      chunks.Build(), PropertyTreeState(t0(), c0(), *e1));
  EXPECT_THAT(output, ElementsAre(PaintOpEq<cc::SaveLayerAlphaOp>(
                                      SkRect::MakeXYWH(0, 0, 100, 100),
                                      0.5f),  // <e2>
                                  PaintOpIs<cc::SaveOp>(),
                                  PaintOpIs<cc::ClipRectOp>(),    // <c1>
                                  PaintOpIs<cc::DrawRecordOp>(),  // <p0/>
                                  PaintOpIs<cc::RestoreOp>(),     // </c1>
                                  PaintOpIs<cc::RestoreOp>()));   // </e2>
}

TEST_P(PaintChunksToCcLayerTest,
       EffectWithNoOutputClipNestedInCompositedEffectAndClip) {
  auto* c1 = CreateClip(c0(), t0(), FloatRoundedRect(0.f, 0.f, 1.f, 1.f));
  auto* e1 = CreateOpacityEffect(e0(), 0.5);
  auto* e2 = CreateOpacityEffect(*e1, t0(), nullptr, 0.5);

  TestChunks chunks;
  chunks.AddChunk(t0(), *c1, *e2);

  PaintRecord output = PaintChunksToCcLayer::Convert(
      chunks.Build(), PropertyTreeState(t0(), *c1, *e1));
  EXPECT_THAT(output, ElementsAre(PaintOpEq<cc::SaveLayerAlphaOp>(
                                      SkRect::MakeXYWH(0, 0, 100, 100),
                                      0.5f),                      // <e2>
                                  PaintOpIs<cc::DrawRecordOp>(),  // <p0/>
                                  PaintOpIs<cc::RestoreOp>()));   // </e2>
}

TEST_P(PaintChunksToCcLayerTest, VisualRect) {
  auto* layer_transform = CreateTransform(t0(), MakeScaleMatrix(20));
  auto* chunk_transform = Create2DTranslation(*layer_transform, 50, 100);

  TestChunks chunks;
  chunks.AddChunk(*chunk_transform, c0(), e0());

  auto cc_list = base::MakeRefCounted<cc::DisplayItemList>();
  PaintChunksToCcLayer::ConvertInto(
      chunks.Build(), PropertyTreeState(*layer_transform, c0(), e0()),
      gfx::Vector2dF(100, 200), nullptr, *cc_list);
  EXPECT_EQ(gfx::Rect(-50, -100, 100, 100), cc_list->VisualRectForTesting(4));

  EXPECT_THAT(cc_list->FinalizeAndReleaseAsRecordForTesting(),
              ElementsAre(PaintOpIs<cc::SaveOp>(),        //
                          PaintOpIs<cc::TranslateOp>(),   // <layer_offset>
                          PaintOpIs<cc::SaveOp>(),        //
                          PaintOpIs<cc::TranslateOp>(),   // <layer_transform>
                          PaintOpIs<cc::DrawRecordOp>(),  // <p0/>
                          PaintOpIs<cc::RestoreOp>(),     // </layer_transform>
                          PaintOpIs<cc::RestoreOp>()));   // </layer_offset>
}

TEST_P(PaintChunksToCcLayerTest, NoncompositedClipPath) {
  auto* c1 = CreateClipPathClip(c0(), t0(), FloatRoundedRect(1, 2, 3, 4));
  TestChunks chunks;
  chunks.AddChunk(t0(), *c1, e0());

  auto output =
      PaintChunksToCcLayer::Convert(chunks.Build(), PropertyTreeState::Root());

  EXPECT_THAT(output,
              ElementsAre(PaintOpIs<cc::SaveOp>(),        //
                          PaintOpIs<cc::ClipRectOp>(),    //
                          PaintOpIs<cc::ClipPathOp>(),    // <clip_path>
                          PaintOpIs<cc::DrawRecordOp>(),  // <p0/>
                          PaintOpIs<cc::RestoreOp>()));   // </clip_path>
}

TEST_P(PaintChunksToCcLayerTest, EmptyClipsAreElided) {
  auto* c1 = CreateClip(c0(), t0(), FloatRoundedRect(0.f, 0.f, 1.f, 1.f));
  auto* c1c2 = CreateClip(*c1, t0(), FloatRoundedRect(0.f, 0.f, 1.f, 1.f));
  auto* c2 = CreateClip(c0(), t0(), FloatRoundedRect(0.f, 0.f, 1.f, 1.f));

  TestChunks chunks;
  chunks.AddChunk(PaintRecord(), t0(), *c1, e0());
  chunks.AddChunk(PaintRecord(), t0(), *c1c2, e0());
  chunks.AddChunk(PaintRecord(), t0(), *c1c2, e0());
  chunks.AddChunk(PaintRecord(), t0(), *c1c2, e0());
  chunks.AddChunk(PaintRecord(), t0(), *c1, e0());
  // D1
  chunks.AddChunk(t0(), *c2, e0());

  PaintRecord output =
      PaintChunksToCcLayer::Convert(chunks.Build(), PropertyTreeState::Root());

  // Note that c1 and c1c2 are elided.
  EXPECT_THAT(output, ElementsAre(PaintOpIs<cc::SaveOp>(),        //
                                  PaintOpIs<cc::ClipRectOp>(),    // <c2>
                                  PaintOpIs<cc::DrawRecordOp>(),  // D1
                                  PaintOpIs<cc::RestoreOp>()      // </c2>
                                  ));
}

TEST_P(PaintChunksToCcLayerTest, NonEmptyClipsAreStored) {
  auto* c1 = CreateClip(c0(), t0(), FloatRoundedRect(0.f, 0.f, 1.f, 1.f));
  auto* c1c2 = CreateClip(*c1, t0(), FloatRoundedRect(0.f, 0.f, 1.f, 1.f));
  auto* c2 = CreateClip(c0(), t0(), FloatRoundedRect(0.f, 0.f, 1.f, 1.f));

  TestChunks chunks;
  chunks.AddChunk(PaintRecord(), t0(), *c1, e0());
  chunks.AddChunk(PaintRecord(), t0(), *c1c2, e0());
  chunks.AddChunk(PaintRecord(), t0(), *c1c2, e0());
  // D1
  chunks.AddChunk(t0(), *c1c2, e0());
  chunks.AddChunk(PaintRecord(), t0(), *c1, e0());
  // D2
  chunks.AddChunk(t0(), *c2, e0());

  PaintRecord output =
      PaintChunksToCcLayer::Convert(chunks.Build(), PropertyTreeState::Root());

  EXPECT_THAT(output, ElementsAre(PaintOpIs<cc::SaveOp>(),
                                  PaintOpIs<cc::ClipRectOp>(),    // <c1+c2>
                                  PaintOpIs<cc::DrawRecordOp>(),  // D1
                                  PaintOpIs<cc::RestoreOp>(),     // </c1+c2>
                                  PaintOpIs<cc::SaveOp>(),
                                  PaintOpIs<cc::ClipRectOp>(),    // <c2>
                                  PaintOpIs<cc::DrawRecordOp>(),  // D2
                                  PaintOpIs<cc::RestoreOp>()      // </c2>
                                  ));
}

TEST_P(PaintChunksToCcLayerTest, EmptyEffectsAreStored) {
  auto* e1 = CreateOpacityEffect(e0(), 0.5);

  TestChunks chunks;
  chunks.AddChunk(PaintRecord(), t0(), c0(), e0());
  chunks.AddChunk(PaintRecord(), t0(), c0(), *e1);

  PaintRecord output =
      PaintChunksToCcLayer::Convert(chunks.Build(), PropertyTreeState::Root());

  EXPECT_THAT(output, ElementsAre(PaintOpEq<cc::SaveLayerAlphaOp>(
                                      SkRect::MakeXYWH(0, 0, 100, 100),
                                      0.5f),                  // <e1>
                                  PaintOpIs<cc::RestoreOp>()  // </e1>
                                  ));
}

TEST_P(PaintChunksToCcLayerTest, CombineClips) {
  FloatRoundedRect clip_rect(0, 0, 100, 100);
  auto* t1 = CreateTransform(t0(), MakeScaleMatrix(2));
  auto* c1 = CreateClip(c0(), t0(), clip_rect);
  auto* c2 = CreateClip(*c1, t0(), clip_rect);
  auto* c3 = CreateClip(*c2, *t1, clip_rect);
  auto* c4 = CreateClip(*c3, *t1, clip_rect);
  auto* c5 = CreateClipPathClip(*c4, *t1, clip_rect);
  auto* c6 = CreateClip(*c5, *t1, clip_rect);

  TestChunks chunks;
  chunks.AddChunk(*t1, *c6, e0());
  chunks.AddChunk(*t1, *c3, e0());

  PaintRecord output =
      PaintChunksToCcLayer::Convert(chunks.Build(), PropertyTreeState::Root());

  EXPECT_THAT(
      output,
      ElementsAre(PaintOpIs<cc::SaveOp>(),
                  PaintOpIs<cc::ClipRectOp>(),  // <c1+c2>
                  PaintOpIs<cc::SaveOp>(), PaintOpIs<cc::ConcatOp>(),  // <t1
                  PaintOpIs<cc::ClipRectOp>(),
                  PaintOpIs<cc::ClipPathOp>(),  //  c3+c4+c5>
                  PaintOpIs<cc::SaveOp>(), PaintOpIs<cc::ClipRectOp>(),  // <c6>
                  PaintOpIs<cc::DrawRecordOp>(),  // <p0/>
                  PaintOpIs<cc::RestoreOp>(),     // </c6>
                  PaintOpIs<cc::RestoreOp>(),     // </c3+c4+c5 t1>
                  PaintOpIs<cc::SaveOp>(), PaintOpIs<cc::ConcatOp>(),  // <t1
                  PaintOpIs<cc::ClipRectOp>(),                         // c3>
                  PaintOpIs<cc::DrawRecordOp>(),                       // <p1/>
                  PaintOpIs<cc::RestoreOp>(),    // </c3 t1>
                  PaintOpIs<cc::RestoreOp>()));  // </c1+c2>
}

TEST_P(PaintChunksToCcLayerTest, CombineClipsAcrossTransform) {
  FloatRoundedRect clip_rect(0, 0, 100, 100);
  auto* identity = Create2DTranslation(t0(), 0, 0);
  auto* non_identity = CreateTransform(*identity, MakeScaleMatrix(2));
  auto* non_invertible = CreateTransform(*non_identity, MakeScaleMatrix(0));
  EXPECT_FALSE(non_invertible->Matrix().IsInvertible());
  auto* c1 = CreateClip(c0(), t0(), FloatRoundedRect(0, 0, 100, 100));
  auto* c2 = CreateClip(*c1, *identity, FloatRoundedRect(50, 50, 100, 100));
  auto* c3 = CreateClip(*c2, *non_identity, FloatRoundedRect(1, 2, 3, 4));
  auto* c4 = CreateClip(*c3, *non_invertible, FloatRoundedRect(5, 6, 7, 8));

  TestChunks chunks;
  chunks.AddChunk(*non_invertible, *c4, e0());

  PaintRecord output =
      PaintChunksToCcLayer::Convert(chunks.Build(), PropertyTreeState::Root());

  // We combine c1/c2 across |identity|, but not c2/c3 across |non_identity|
  // and c3/c4 across |non_invertible|.
  EXPECT_THAT(
      output,
      ElementsAre(PaintOpIs<cc::SaveOp>(),
                  PaintOpEq<cc::ClipRectOp>(SkRect::MakeXYWH(50, 50, 50, 50),
                                            SkClipOp::kIntersect,
                                            /*antialias=*/true),  // <c1+c2>
                  PaintOpIs<cc::SaveOp>(),
                  PaintOpEq<cc::ConcatOp>(gfx::TransformToSkM44(
                      non_identity->Matrix())),  // <non_identity
                  PaintOpEq<cc::ClipRectOp>(SkRect::MakeXYWH(1, 2, 3, 4),
                                            SkClipOp::kIntersect,
                                            /*antialias=*/true),  //  c3>
                  PaintOpIs<cc::SaveOp>(),
                  PaintOpEq<cc::ConcatOp>(gfx::TransformToSkM44(
                      non_invertible->Matrix())),  // <non_invertible
                  PaintOpEq<cc::ClipRectOp>(SkRect::MakeXYWH(5, 6, 7, 8),
                                            SkClipOp::kIntersect,
                                            /*antialias=*/true),  //  c4>
                  PaintOpIs<cc::DrawRecordOp>(),                  // <p0/>
                  PaintOpIs<cc::RestoreOp>(),  // </c4 non_invertible>
                  PaintOpIs<cc::RestoreOp>(),  // </c3 non_identity>
                  PaintOpIs<cc::RestoreOp>()   // </c1+c2>
                  ));
}

TEST_P(PaintChunksToCcLayerTest, CombineClipsWithRoundedRects) {
  FloatRoundedRect rect(0, 0, 100, 100);
  FloatRoundedRect big_rounded_rect(gfx::RectF(0, 0, 200, 200), 5);
  FloatRoundedRect small_rounded_rect(gfx::RectF(0, 0, 100, 100), 5);

  auto* c1 = CreateClip(c0(), t0(), rect);
  auto* c2 = CreateClip(*c1, t0(), small_rounded_rect);
  auto* c3 = CreateClip(*c2, t0(), rect);
  auto* c4 = CreateClip(*c3, t0(), big_rounded_rect);
  auto* c5 = CreateClip(*c4, t0(), rect);
  auto* c6 = CreateClip(*c5, t0(), big_rounded_rect);
  auto* c7 = CreateClip(*c6, t0(), small_rounded_rect);

  TestChunks chunks;
  chunks.AddChunk(t0(), *c7, e0());

  PaintRecord output =
      PaintChunksToCcLayer::Convert(chunks.Build(), PropertyTreeState::Root());

  EXPECT_THAT(
      output,
      ElementsAre(PaintOpIs<cc::SaveOp>(),
                  PaintOpEq<cc::ClipRRectOp>(SkRRect(small_rounded_rect),
                                             SkClipOp::kIntersect,
                                             /*antialias=*/true),  // <c1+c2+c3>
                  PaintOpIs<cc::SaveOp>(),
                  PaintOpEq<cc::ClipRRectOp>(SkRRect(big_rounded_rect),
                                             SkClipOp::kIntersect,
                                             /*antialias=*/true),  // <c4>
                  PaintOpIs<cc::SaveOp>(),
                  PaintOpEq<cc::ClipRectOp>(gfx::RectFToSkRect(rect.Rect()),
                                            SkClipOp::kIntersect,
                                            /*antialias=*/true),  // <c5>
                  PaintOpIs<cc::SaveOp>(),
                  PaintOpEq<cc::ClipRRectOp>(SkRRect(big_rounded_rect),
                                             SkClipOp::kIntersect,
                                             /*antialias=*/true),  // <c6>
                  PaintOpIs<cc::SaveOp>(),
                  PaintOpEq<cc::ClipRRectOp>(SkRRect(small_rounded_rect),
                                             SkClipOp::kIntersect,
                             
"""


```