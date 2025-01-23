Response:
The user wants to understand the functionality of the `paint_artifact_compositor_test.cc` file in the Chromium Blink engine. I need to:

1. **Identify the primary purpose of the file:** Based on the name, it's a test file for the `PaintArtifactCompositor`.
2. **Summarize the functionalities tested:** This involves looking at the included headers, the test class setup, and the individual test cases (even though the provided snippet is incomplete).
3. **Determine its relation to JavaScript, HTML, and CSS:**  Consider how compositing and paint artifacts relate to these web technologies.
4. **Infer logical reasoning with hypothetical inputs and outputs:** While the provided snippet doesn't show full test cases, I can infer the general testing approach.
5. **Identify common usage errors:**  Think about potential errors when dealing with compositing and rendering.
6. **Summarize the functionality of the provided code snippet:** This will be the main focus of this first part.
The file `paint_artifact_compositor_test.cc` is a **unit test file** for the `PaintArtifactCompositor` class within the Chromium Blink rendering engine. Its primary function is to **verify the correct behavior of the `PaintArtifactCompositor`** in various scenarios.

Here's a breakdown of its functionalities based on the included headers and the test structure:

**Core Functionality Being Tested:**

* **Compositing of Paint Artifacts:** The tests aim to ensure that the `PaintArtifactCompositor` correctly translates a `PaintArtifact` (which represents painting instructions) into a composited layer tree structure in Chromium's rendering pipeline. This involves creating `cc::Layer` objects and setting their properties.
* **Property Tree Integration:** The tests heavily interact with Chromium's property trees (`cc::PropertyTrees`), specifically testing how the `PaintArtifactCompositor` populates the transform, clip, effect, and scroll property trees based on the information within the `PaintArtifact`.
* **Transformations:**  Tests verify how different transformations (translations, rotations, scaling) defined in the `PaintArtifact` are applied to the composited layers. This includes testing transform combining, backface visibility, and the `flattens_inherited_transform` property.
* **Clipping:** Tests check if clipping regions defined in the `PaintArtifact` are correctly applied to the layers, ensuring content outside the clip is not rendered. This includes testing nested clips.
* **Effects (Opacity, Masks, Filters):** While not explicitly demonstrated in this snippet, the inclusion of `<third_party/blink/renderer/platform/graphics/paint/effect_paint_property_node.h>` and `cc/trees/effect_node.h` suggests that the tests also cover how the compositor handles visual effects like opacity, masks, and filters.
* **Scrolling:** The presence of `cc/trees/scroll_node.h` and the `MockScrollCallbacks` class indicates that the tests verify how scrollable areas defined in the `PaintArtifact` are handled and how scroll events are propagated.
* **LCD Text Preference:**  The `SetLCDTextPreference` call suggests tests around how the compositor handles different LCD text rendering preferences.
* **Invisibility:** The `UpdateWithEffectivelyInvisibleChunk` test checks how the compositor handles parts of the paint artifact marked as effectively invisible.

**Relationship to JavaScript, HTML, and CSS:**

The `PaintArtifactCompositor` plays a crucial role in rendering web content defined by HTML, styled by CSS, and potentially manipulated by JavaScript. Here are some examples:

* **HTML Structure:** The HTML document structure, especially elements that create stacking contexts or have specific CSS properties applied, directly influences the creation and structure of the `PaintArtifact`. For instance, a `<div>` with `position: fixed` or `transform` will likely result in a separate composited layer.
* **CSS Styling:** CSS properties like `transform`, `opacity`, `clip-path`, `overflow: scroll`, and filters directly translate into properties within the `PaintArtifact` and subsequently influence the `cc::Layer` properties and property tree nodes created by the `PaintArtifactCompositor`.
    * **Example (CSS Transform):** A CSS rule like `transform: rotate(45deg);` on an HTML element would lead to a `TransformPaintPropertyNode` in the `PaintArtifact`. The test `TEST_P(PaintArtifactCompositorTest, OneTransform)` verifies that the `PaintArtifactCompositor` correctly creates a `cc::Layer` with the corresponding transformation applied.
    * **Example (CSS Clip):**  A CSS rule like `clip-path: rectangle(10px, 10px, 100px, 100px);` would result in a `ClipPaintPropertyNode`. The test `TEST_P(PaintArtifactCompositorTest, OneClip)` checks if the compositor creates a layer with the correct clipping bounds.
* **JavaScript Animations and Interactions:** JavaScript can dynamically modify CSS properties, triggering repaints and updates to the `PaintArtifact`. For example, a JavaScript animation that changes the `transform` property of an element will cause the `PaintArtifactCompositor` to update the corresponding layer's transformation. The tests ensure that these updates are handled correctly.

**Logical Reasoning (Hypothetical Input and Output):**

Let's consider the `TEST_P(PaintArtifactCompositorTest, OneChunkWithAnOffset)` test:

* **Hypothetical Input:** A `PaintArtifact` containing a single "chunk" of painting instructions to draw a white rectangle of size 100x100, offset by (50, -50).
* **Expected Output:** The `PaintArtifactCompositor` should create one `cc::Layer`. This layer should:
    * Have a picture that draws a 100x100 white rectangle.
    * Have a screen space transformation that translates the layer by (50, -50).
    * Have bounds of 100x100.
    * Have a transform node in the property tree that indicates no transform change beyond the initial offset.

**Common Usage Errors (Hypothetical):**

While this test file is for the *internal implementation*, we can think about potential issues a developer *using* the rendering engine might encounter, which these tests indirectly help prevent:

* **Incorrectly specifying transformation origins:**  If the transformation origin in CSS or the `PaintArtifact` is wrong, the composited layer might rotate or scale around an unexpected point. The tests with transformations likely cover various origin scenarios.
* **Forgetting to account for stacking contexts:** If a developer doesn't properly understand how CSS stacking contexts influence layer creation, they might expect certain elements to be drawn on top of others, but the compositor might create a different layer order. While not directly tested here, the compositor's logic for handling stacking contexts is crucial.
* **Performance issues due to excessive layer creation:**  Certain CSS properties can inadvertently trigger the creation of many composited layers, leading to performance problems. The `PaintArtifactCompositor` needs to be efficient in managing layer creation.
* **Incorrectly defining clipping regions:** A mistake in defining the `clip-path` or `overflow` properties could lead to content being clipped unexpectedly or not being clipped when it should be.

**Summary of the Provided Code Snippet's Functionality (Part 1):**

This first part of `paint_artifact_compositor_test.cc` sets up the testing environment for verifying the `PaintArtifactCompositor`. It includes:

* **Includes necessary headers:**  These headers provide access to the `PaintArtifactCompositor`, property tree classes, layer classes, testing utilities, and graphics primitives.
* **Defines a `MockScrollCallbacks` class:** This allows for mocking the callbacks used by the compositor for scroll-related events, enabling verification of scroll behavior.
* **Defines the `PaintArtifactCompositorTest` fixture:** This class inherits from `testing::Test` and `PaintTestConfigurations`, providing a framework for writing individual test cases.
* **Sets up the testing environment in `SetUp()`:** This includes creating a `PaintArtifactCompositor` instance, setting the LCD text preference, and creating a `LayerTreeHostEmbedder` to simulate the Chromium compositing environment.
* **Provides helper functions:**  Functions like `GetPropertyTrees()`, `GetTransformNode()`, `Update()`, `LayerAt()`, etc., simplify interacting with the compositor and the resulting layer tree within the tests. These helpers make the test code more readable and maintainable.

In essence, this initial part lays the foundation for writing focused unit tests that examine specific aspects of the `PaintArtifactCompositor`'s functionality in translating paint instructions into a composited layer tree structure.

### 提示词
```
这是目录为blink/renderer/platform/graphics/compositing/paint_artifact_compositor_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/graphics/compositing/paint_artifact_compositor.h"

#include <memory>

#include "base/containers/adapters.h"
#include "base/memory/ptr_util.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/test_simple_task_runner.h"
#include "build/build_config.h"
#include "cc/input/main_thread_scrolling_reason.h"
#include "cc/layers/layer.h"
#include "cc/test/fake_impl_task_runner_provider.h"
#include "cc/test/fake_layer_tree_frame_sink.h"
#include "cc/test/fake_layer_tree_host_client.h"
#include "cc/test/fake_layer_tree_host_impl.h"
#include "cc/trees/clip_node.h"
#include "cc/trees/effect_node.h"
#include "cc/trees/layer_tree_host.h"
#include "cc/trees/layer_tree_settings.h"
#include "cc/trees/property_tree.h"
#include "cc/trees/scroll_node.h"
#include "cc/trees/transform_node.h"
#include "cc/view_transition/view_transition_request.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/graphics/paint/effect_paint_property_node.h"
#include "third_party/blink/renderer/platform/graphics/paint/geometry_mapper.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_artifact.h"
#include "third_party/blink/renderer/platform/graphics/paint/scroll_paint_property_node.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/testing/fake_display_item_client.h"
#include "third_party/blink/renderer/platform/testing/layer_tree_host_embedder.h"
#include "third_party/blink/renderer/platform/testing/paint_property_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/paint_test_configurations.h"
#include "third_party/blink/renderer/platform/testing/picture_matchers.h"
#include "third_party/blink/renderer/platform/testing/test_paint_artifact.h"
#include "third_party/blink/renderer/platform/wtf/allocator/allocator.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "ui/gfx/geometry/test/geometry_util.h"

namespace blink {
namespace {

using testing::ElementsAre;
using testing::Pointee;

gfx::Transform Translation(SkScalar x, SkScalar y) {
  gfx::Transform transform;
  transform.Translate(x, y);
  return transform;
}

class MockScrollCallbacks : public CompositorScrollCallbacks {
 public:
  MOCK_METHOD3(DidCompositorScroll,
               void(CompositorElementId,
                    const gfx::PointF&,
                    const std::optional<cc::TargetSnapAreaElementIds>&));
  MOCK_METHOD2(DidChangeScrollbarsHidden, void(CompositorElementId, bool));

  base::WeakPtr<MockScrollCallbacks> GetWeakPtr() {
    return weak_ptr_factory_.GetWeakPtr();
  }

 private:
  base::WeakPtrFactory<MockScrollCallbacks> weak_ptr_factory_{this};
};

class PaintArtifactCompositorTest : public testing::Test,
                                    public PaintTestConfigurations {
 protected:
  PaintArtifactCompositorTest()
      : task_runner_(base::MakeRefCounted<base::TestSimpleTaskRunner>()),
        task_runner_current_default_handle_(task_runner_) {}

  void SetUp() override {
    // Delay constructing the compositor until after the feature is set.
    paint_artifact_compositor_ = MakeGarbageCollected<PaintArtifactCompositor>(
        scroll_callbacks_.GetWeakPtr());
    // Prefer lcd-text by default for tests.
    paint_artifact_compositor_->SetLCDTextPreference(
        LCDTextPreference::kStronglyPreferred);

    // Uses a LayerTreeHostClient that will make a LayerTreeFrameSink to allow
    // the compositor to run and submit frames.
    layer_tree_ = std::make_unique<LayerTreeHostEmbedder>(
        &layer_tree_host_client_,
        /*single_thread_client=*/nullptr);
    layer_tree_host_client_.SetLayerTreeHost(layer_tree_->layer_tree_host());
    layer_tree_->layer_tree_host()->SetRootLayer(
        paint_artifact_compositor_->RootLayer());
  }

  void TearDown() override {
    // Make sure we remove all child layers to satisfy destructor
    // child layer element id DCHECK.
    WillBeRemovedFromFrame();
    layer_tree_host_client_.SetLayerTreeHost(nullptr);
  }

  cc::PropertyTrees& GetPropertyTrees() {
    return *layer_tree_->layer_tree_host()->property_trees();
  }

  const cc::TransformNode& GetTransformNode(const cc::Layer* layer) {
    return *GetPropertyTrees().transform_tree().Node(
        layer->transform_tree_index());
  }

  const cc::EffectNode& GetEffectNode(const cc::Layer* layer) {
    return *GetPropertyTrees().effect_tree().Node(layer->effect_tree_index());
  }

  cc::LayerTreeHost& GetLayerTreeHost() {
    return *layer_tree_->layer_tree_host();
  }

  int ElementIdToEffectNodeIndex(CompositorElementId element_id) {
    auto* property_trees = layer_tree_->layer_tree_host()->property_trees();
    const auto* node =
        property_trees->effect_tree().FindNodeFromElementId(element_id);
    return node ? node->id : -1;
  }

  int ElementIdToTransformNodeIndex(CompositorElementId element_id) {
    auto* property_trees = layer_tree_->layer_tree_host()->property_trees();
    const auto* node =
        property_trees->transform_tree().FindNodeFromElementId(element_id);
    return node ? node->id : -1;
  }

  int ElementIdToScrollNodeIndex(CompositorElementId element_id) {
    auto* property_trees = layer_tree_->layer_tree_host()->property_trees();
    const auto* node =
        property_trees->scroll_tree().FindNodeFromElementId(element_id);
    return node ? node->id : -1;
  }

  using ViewportProperties = PaintArtifactCompositor::ViewportProperties;

  void Update(
      const PaintArtifact& artifact,
      const ViewportProperties& viewport_properties = ViewportProperties(),
      const PaintArtifactCompositor::StackScrollTranslationVector&
          scroll_translation_nodes = {}) {
    paint_artifact_compositor_->SetNeedsUpdate();
    paint_artifact_compositor_->Update(artifact, viewport_properties,
                                       scroll_translation_nodes, {});
    layer_tree_->layer_tree_host()->LayoutAndUpdateLayers();
  }

  void WillBeRemovedFromFrame() {
    paint_artifact_compositor_->WillBeRemovedFromFrame();
  }

  cc::Layer* RootLayer() { return paint_artifact_compositor_->RootLayer(); }

  // Returns the |num|th scroll hit test layer.
  cc::Layer* ScrollHitTestLayerAt(size_t num) {
    const cc::ScrollTree& scroll_tree = GetPropertyTrees().scroll_tree();
    for (auto& layer : RootLayer()->children()) {
      if (scroll_tree.FindNodeFromElementId(layer->element_id())) {
        if (num == 0)
          return layer.get();
        num--;
      }
    }
    return nullptr;
  }

  // Returns the |num|th non-scrollable content layer.
  cc::Layer* NonScrollHitTestLayerAt(size_t num) {
    const cc::ScrollTree& scroll_tree = GetPropertyTrees().scroll_tree();
    for (auto& layer : RootLayer()->children()) {
      if (!scroll_tree.FindNodeFromElementId(layer->element_id())) {
        if (num == 0)
          return layer.get();
        num--;
      }
    }
    return nullptr;
  }

  size_t LayerCount() { return RootLayer()->children().size(); }

  cc::Layer* LayerAt(unsigned index) {
    return RootLayer()->children()[index].get();
  }

  size_t SynthesizedClipLayerCount() {
    return paint_artifact_compositor_->SynthesizedClipLayersForTesting().size();
  }

  cc::Layer* SynthesizedClipLayerAt(unsigned index) {
    return paint_artifact_compositor_->SynthesizedClipLayersForTesting()[index];
  }

  // Return the index of |layer| in the root layer list, or -1 if not found.
  int LayerIndex(const cc::Layer* layer) {
    int i = 0;
    for (auto& child : RootLayer()->children()) {
      if (child.get() == layer)
        return i;
      i++;
    }
    return -1;
  }

  void UpdateWithEffectivelyInvisibleChunk(bool include_preceding_chunk,
                                           bool include_subsequent_chunk) {
    TestPaintArtifact artifact;
    if (include_preceding_chunk)
      artifact.Chunk().RectDrawing(gfx::Rect(0, 0, 10, 10), Color::kBlack);
    artifact.Chunk().EffectivelyInvisible().RectDrawing(
        gfx::Rect(10, 0, 10, 10), Color(255, 0, 0));
    if (include_subsequent_chunk)
      artifact.Chunk().RectDrawing(gfx::Rect(0, 10, 10, 10), Color::kWhite);
    Update(artifact.Build());
  }

  MockScrollCallbacks& ScrollCallbacks() { return scroll_callbacks_; }

  PaintArtifactCompositor& GetPaintArtifactCompositor() {
    return *paint_artifact_compositor_;
  }

  int CcNodeId(const PaintPropertyNode& node) {
    return node.CcNodeId(GetPropertyTrees().sequence_number());
  }

 private:
  MockScrollCallbacks scroll_callbacks_;
  Persistent<PaintArtifactCompositor> paint_artifact_compositor_;
  scoped_refptr<base::TestSimpleTaskRunner> task_runner_;
  base::SingleThreadTaskRunner::CurrentDefaultHandle
      task_runner_current_default_handle_;
  cc::FakeLayerTreeHostClient layer_tree_host_client_;
  std::unique_ptr<LayerTreeHostEmbedder> layer_tree_;
};

INSTANTIATE_PAINT_TEST_SUITE_P(PaintArtifactCompositorTest);

const auto kNotScrollingOnMain =
    cc::MainThreadScrollingReason::kNotScrollingOnMain;

TEST_P(PaintArtifactCompositorTest, EmptyPaintArtifact) {
  Update(*MakeGarbageCollected<PaintArtifact>());
  EXPECT_TRUE(RootLayer()->children().empty());
}

TEST_P(PaintArtifactCompositorTest, OneChunkWithAnOffset) {
  TestPaintArtifact artifact;
  artifact.Chunk().RectDrawing(gfx::Rect(50, -50, 100, 100), Color::kWhite);
  Update(artifact.Build());

  ASSERT_EQ(1u, LayerCount());
  const cc::Layer* child = LayerAt(0);
  EXPECT_THAT(
      child->GetPicture(),
      Pointee(DrawsRectangle(gfx::RectF(0, 0, 100, 100), Color::kWhite)));
  EXPECT_EQ(Translation(50, -50), child->ScreenSpaceTransform());
  EXPECT_EQ(gfx::Size(100, 100), child->bounds());
  EXPECT_FALSE(GetTransformNode(child).transform_changed);
}

TEST_P(PaintArtifactCompositorTest, OneTransform) {
  // A 90 degree clockwise rotation about (100, 100).
  auto* transform =
      CreateTransform(t0(), MakeRotationMatrix(90), gfx::Point3F(100, 100, 0),
                      CompositingReason::k3DTransform);

  TestPaintArtifact artifact;
  artifact.Chunk(*transform, c0(), e0())
      .RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kWhite);
  artifact.Chunk().RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kGray);
  artifact.Chunk(*transform, c0(), e0())
      .RectDrawing(gfx::Rect(100, 0, 100, 100), Color::kBlack);
  Update(artifact.Build());

  ASSERT_EQ(2u, LayerCount());
  {
    const cc::Layer* layer = LayerAt(0);
    EXPECT_TRUE(GetTransformNode(layer).transform_changed);

    Vector<RectWithColor> rects_with_color;
    rects_with_color.push_back(
        RectWithColor(gfx::RectF(0, 0, 100, 100), Color::kWhite));
    rects_with_color.push_back(
        RectWithColor(gfx::RectF(100, 0, 100, 100), Color::kBlack));

    EXPECT_THAT(layer->GetPicture(),
                Pointee(DrawsRectangles(rects_with_color)));
    EXPECT_EQ(
        gfx::RectF(100, 0, 100, 100),
        layer->ScreenSpaceTransform().MapRect(gfx::RectF(0, 0, 100, 100)));
  }
  {
    const cc::Layer* layer = LayerAt(1);
    EXPECT_FALSE(GetTransformNode(layer).transform_changed);
    EXPECT_THAT(
        layer->GetPicture(),
        Pointee(DrawsRectangle(gfx::RectF(0, 0, 100, 100), Color::kGray)));
    EXPECT_EQ(gfx::Transform(), layer->ScreenSpaceTransform());
  }
}

TEST_P(PaintArtifactCompositorTest, OneTransformWithAlias) {
  // A 90 degree clockwise rotation about (100, 100).
  auto* real_transform =
      CreateTransform(t0(), MakeRotationMatrix(90), gfx::Point3F(100, 100, 0),
                      CompositingReason::k3DTransform);
  auto* transform = TransformPaintPropertyNodeAlias::Create(*real_transform);

  TestPaintArtifact artifact;
  artifact.Chunk(*transform, c0(), e0())
      .RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kWhite);
  artifact.Chunk().RectDrawing(gfx::Rect(0, 0, 100, 100), Color::kGray);
  artifact.Chunk(*transform, c0(), e0())
      .RectDrawing(gfx::Rect(100, 0, 100, 100), Color::kBlack);
  Update(artifact.Build());

  ASSERT_EQ(2u, LayerCount());
  {
    const cc::Layer* layer = LayerAt(0);
    EXPECT_TRUE(GetTransformNode(layer).transform_changed);

    Vector<RectWithColor> rects_with_color;
    rects_with_color.push_back(
        RectWithColor(gfx::RectF(0, 0, 100, 100), Color::kWhite));
    rects_with_color.push_back(
        RectWithColor(gfx::RectF(100, 0, 100, 100), Color::kBlack));

    EXPECT_THAT(layer->GetPicture(),
                Pointee(DrawsRectangles(rects_with_color)));
    EXPECT_EQ(
        gfx::RectF(100, 0, 100, 100),
        layer->ScreenSpaceTransform().MapRect(gfx::RectF(0, 0, 100, 100)));
  }
  {
    const cc::Layer* layer = LayerAt(1);
    EXPECT_FALSE(GetTransformNode(layer).transform_changed);
    EXPECT_THAT(
        layer->GetPicture(),
        Pointee(DrawsRectangle(gfx::RectF(0, 0, 100, 100), Color::kGray)));
    EXPECT_EQ(gfx::Transform(), layer->ScreenSpaceTransform());
  }
}

TEST_P(PaintArtifactCompositorTest, TransformCombining) {
  // A translation by (5, 5) within a 2x scale about (10, 10).
  auto* transform1 =
      CreateTransform(t0(), MakeScaleMatrix(2), gfx::Point3F(10, 10, 0),
                      CompositingReason::k3DTransform);
  auto* transform2 =
      CreateTransform(*transform1, MakeTranslationMatrix(5, 5), gfx::Point3F(),
                      CompositingReason::kWillChangeTransform);

  TestPaintArtifact artifact;
  artifact.Chunk(*transform1, c0(), e0())
      .RectDrawing(gfx::Rect(0, 0, 300, 200), Color::kWhite);
  artifact.Chunk(*transform2, c0(), e0())
      .RectDrawing(gfx::Rect(0, 0, 300, 200), Color::kBlack);
  Update(artifact.Build());

  ASSERT_EQ(2u, LayerCount());
  {
    const cc::Layer* layer = LayerAt(0);
    EXPECT_TRUE(GetTransformNode(layer).transform_changed);
    EXPECT_THAT(
        layer->GetPicture(),
        Pointee(DrawsRectangle(gfx::RectF(0, 0, 300, 200), Color::kWhite)));
    EXPECT_EQ(
        gfx::RectF(-10, -10, 600, 400),
        layer->ScreenSpaceTransform().MapRect(gfx::RectF(0, 0, 300, 200)));
  }
  {
    const cc::Layer* layer = LayerAt(1);
    EXPECT_TRUE(GetTransformNode(layer).transform_changed);
    EXPECT_THAT(
        layer->GetPicture(),
        Pointee(DrawsRectangle(gfx::RectF(0, 0, 300, 200), Color::kBlack)));
    EXPECT_EQ(gfx::RectF(0, 0, 600, 400), layer->ScreenSpaceTransform().MapRect(
                                              gfx::RectF(0, 0, 300, 200)));
  }
  EXPECT_NE(LayerAt(0)->transform_tree_index(),
            LayerAt(1)->transform_tree_index());
}

TEST_P(PaintArtifactCompositorTest, BackfaceVisibility) {
  TransformPaintPropertyNode::State backface_hidden_state;
  backface_hidden_state.backface_visibility =
      TransformPaintPropertyNode::BackfaceVisibility::kHidden;
  auto* backface_hidden_transform = TransformPaintPropertyNode::Create(
      t0(), std::move(backface_hidden_state));

  auto* backface_inherited_transform = TransformPaintPropertyNode::Create(
      *backface_hidden_transform, TransformPaintPropertyNode::State{});

  TransformPaintPropertyNode::State backface_visible_state;
  backface_visible_state.backface_visibility =
      TransformPaintPropertyNode::BackfaceVisibility::kVisible;
  auto* backface_visible_transform = TransformPaintPropertyNode::Create(
      *backface_hidden_transform, std::move(backface_visible_state));

  TestPaintArtifact artifact;
  artifact.Chunk(*backface_hidden_transform, c0(), e0())
      .RectDrawing(gfx::Rect(0, 0, 300, 200), Color::kWhite);
  artifact.Chunk(*backface_inherited_transform, c0(), e0())
      .RectDrawing(gfx::Rect(100, 100, 100, 100), Color::kBlack);
  artifact.Chunk(*backface_visible_transform, c0(), e0())
      .RectDrawing(gfx::Rect(0, 0, 300, 200), Color::kDarkGray);
  Update(artifact.Build());

  ASSERT_EQ(2u, LayerCount());
  EXPECT_THAT(
      LayerAt(0)->GetPicture(),
      Pointee(DrawsRectangles(Vector<RectWithColor>{
          RectWithColor(gfx::RectF(0, 0, 300, 200), Color::kWhite),
          RectWithColor(gfx::RectF(100, 100, 100, 100), Color::kBlack)})));
  EXPECT_THAT(
      LayerAt(1)->GetPicture(),
      Pointee(DrawsRectangle(gfx::RectF(0, 0, 300, 200), Color::kDarkGray)));
}

TEST_P(PaintArtifactCompositorTest, FlattensInheritedTransform) {
  for (bool transform_is_flattened : {true, false}) {
    SCOPED_TRACE(transform_is_flattened);

    // The flattens_inherited_transform bit corresponds to whether the _parent_
    // transform node flattens the transform. This is because Blink's notion of
    // flattening determines whether content within the node's local transform
    // is flattened, while cc's notion applies in the parent's coordinate space.
    auto* transform1 = CreateTransform(t0(), gfx::Transform());
    auto* transform2 =
        CreateTransform(*transform1, MakeRotationMatrix(0, 45, 0));
    TransformPaintPropertyNode::State transform3_state{
        {MakeRotationMatrix(0, 45, 0)}};
    transform3_state.flattens_inherited_transform = transform_is_flattened;
    auto* transform3 = TransformPaintPropertyNode::Create(
        *transform2, std::move(transform3_state));

    TestPaintArtifact artifact;
    artifact.Chunk(*transform3, c0(), e0())
        .RectDrawing(gfx::Rect(0, 0, 300, 200), Color::kWhite);
    Update(artifact.Build());

    ASSERT_EQ(1u, LayerCount());
    const cc::Layer* layer = LayerAt(0);
    EXPECT_THAT(
        layer->GetPicture(),
        Pointee(DrawsRectangle(gfx::RectF(0, 0, 300, 200), Color::kWhite)));

    // The leaf transform node should flatten its inherited transform node
    // if and only if the intermediate rotation transform in the Blink tree
    // flattens.
    const cc::TransformNode* transform_node3 =
        GetPropertyTrees().transform_tree().Node(layer->transform_tree_index());
    EXPECT_EQ(transform_is_flattened,
              transform_node3->flattens_inherited_transform);

    // Given this, we should expect the correct screen space transform for
    // each case. If the transform was flattened, we should see it getting
    // an effective horizontal scale of 1/sqrt(2) each time, thus it gets
    // half as wide. If the transform was not flattened, we should see an
    // empty rectangle (as the total 90 degree rotation makes it
    // perpendicular to the viewport).
    gfx::RectF rect =
        layer->ScreenSpaceTransform().MapRect(gfx::RectF(0, 0, 100, 100));
    if (transform_is_flattened)
      EXPECT_RECTF_EQ(gfx::RectF(0, 0, 50, 100), rect);
    else
      EXPECT_TRUE(rect.IsEmpty());
  }
}

TEST_P(PaintArtifactCompositorTest, FlattensInheritedTransformWithAlias) {
  for (bool transform_is_flattened : {true, false}) {
    SCOPED_TRACE(transform_is_flattened);

    // The flattens_inherited_transform bit corresponds to whether the _parent_
    // transform node flattens the transform. This is because Blink's notion of
    // flattening determines whether content within the node's local transform
    // is flattened, while cc's notion applies in the parent's coordinate space.
    auto* real_transform1 = CreateTransform(t0(), gfx::Transform());
    auto* transform1 =
        TransformPaintPropertyNodeAlias::Create(*real_transform1);
    auto* real_transform2 =
        CreateTransform(*transform1, MakeRotationMatrix(0, 45, 0));
    auto* transform2 =
        TransformPaintPropertyNodeAlias::Create(*real_transform2);
    TransformPaintPropertyNode::State transform3_state{
        {MakeRotationMatrix(0, 45, 0)}};
    transform3_state.flattens_inherited_transform = transform_is_flattened;
    auto* real_transform3 = TransformPaintPropertyNode::Create(
        *transform2, std::move(transform3_state));
    auto* transform3 =
        TransformPaintPropertyNodeAlias::Create(*real_transform3);

    TestPaintArtifact artifact;
    artifact.Chunk(*transform3, c0(), e0())
        .RectDrawing(gfx::Rect(0, 0, 300, 200), Color::kWhite);
    Update(artifact.Build());

    ASSERT_EQ(1u, LayerCount());
    const cc::Layer* layer = LayerAt(0);
    EXPECT_THAT(
        layer->GetPicture(),
        Pointee(DrawsRectangle(gfx::RectF(0, 0, 300, 200), Color::kWhite)));

    // The leaf transform node should flatten its inherited transform node
    // if and only if the intermediate rotation transform in the Blink tree
    // flattens.
    const cc::TransformNode* transform_node3 =
        GetPropertyTrees().transform_tree().Node(layer->transform_tree_index());
    EXPECT_EQ(transform_is_flattened,
              transform_node3->flattens_inherited_transform);

    // Given this, we should expect the correct screen space transform for
    // each case. If the transform was flattened, we should see it getting
    // an effective horizontal scale of 1/sqrt(2) each time, thus it gets
    // half as wide. If the transform was not flattened, we should see an
    // empty rectangle (as the total 90 degree rotation makes it
    // perpendicular to the viewport).
    gfx::RectF rect =
        layer->ScreenSpaceTransform().MapRect(gfx::RectF(0, 0, 100, 100));
    if (transform_is_flattened)
      EXPECT_RECTF_EQ(gfx::RectF(0, 0, 50, 100), rect);
    else
      EXPECT_TRUE(rect.IsEmpty());
  }
}
TEST_P(PaintArtifactCompositorTest, SortingContextID) {
  // Has no 3D rendering context.
  auto* transform1 = CreateTransform(t0(), gfx::Transform());
  // Establishes a 3D rendering context.
  TransformPaintPropertyNode::State transform2_state;
  transform2_state.rendering_context_id = 1;
  transform2_state.direct_compositing_reasons =
      CompositingReason::kWillChangeTransform;
  auto* transform2 = TransformPaintPropertyNode::Create(
      *transform1, std::move(transform2_state));
  // Extends the 3D rendering context of transform2.
  TransformPaintPropertyNode::State transform3_state;
  transform3_state.rendering_context_id = 1;
  transform3_state.direct_compositing_reasons =
      CompositingReason::kWillChangeTransform;
  auto* transform3 = TransformPaintPropertyNode::Create(
      *transform2, std::move(transform3_state));
  // Establishes a 3D rendering context distinct from transform2.
  TransformPaintPropertyNode::State transform4_state;
  transform4_state.rendering_context_id = 2;
  transform4_state.direct_compositing_reasons =
      CompositingReason::kWillChangeTransform;
  auto* transform4 = TransformPaintPropertyNode::Create(
      *transform2, std::move(transform4_state));

  TestPaintArtifact artifact;
  artifact.Chunk(*transform1, c0(), e0())
      .RectDrawing(gfx::Rect(0, 0, 300, 200), Color::kWhite);
  artifact.Chunk(*transform2, c0(), e0())
      .RectDrawing(gfx::Rect(0, 0, 300, 200), Color::kLightGray);
  artifact.Chunk(*transform3, c0(), e0())
      .RectDrawing(gfx::Rect(0, 0, 300, 200), Color::kDarkGray);
  artifact.Chunk(*transform4, c0(), e0())
      .RectDrawing(gfx::Rect(0, 0, 300, 200), Color::kBlack);
  Update(artifact.Build());

  ASSERT_EQ(4u, LayerCount());

  // The white layer is not 3D sorted.
  const cc::Layer* white_layer = LayerAt(0);
  EXPECT_THAT(
      white_layer->GetPicture(),
      Pointee(DrawsRectangle(gfx::RectF(0, 0, 300, 200), Color::kWhite)));
  int white_sorting_context_id =
      GetTransformNode(white_layer).sorting_context_id;
  EXPECT_EQ(0, white_sorting_context_id);

  // The light gray layer is 3D sorted.
  const cc::Layer* light_gray_layer = LayerAt(1);
  EXPECT_THAT(
      light_gray_layer->GetPicture(),
      Pointee(DrawsRectangle(gfx::RectF(0, 0, 300, 200), Color::kLightGray)));
  int light_gray_sorting_context_id =
      GetTransformNode(light_gray_layer).sorting_context_id;
  EXPECT_NE(0, light_gray_sorting_context_id);

  // The dark gray layer is 3D sorted with the light gray layer, but has a
  // separate transform node.
  const cc::Layer* dark_gray_layer = LayerAt(2);
  EXPECT_THAT(
      dark_gray_layer->GetPicture(),
      Pointee(DrawsRectangle(gfx::RectF(0, 0, 300, 200), Color::kDarkGray)));
  int dark_gray_sorting_context_id =
      GetTransformNode(dark_gray_layer).sorting_context_id;
  EXPECT_EQ(light_gray_sorting_context_id, dark_gray_sorting_context_id);
  EXPECT_NE(light_gray_layer->transform_tree_index(),
            dark_gray_layer->transform_tree_index());

  // The black layer is 3D sorted, but in a separate context from the previous
  // layers.
  const cc::Layer* black_layer = LayerAt(3);
  EXPECT_THAT(
      black_layer->GetPicture(),
      Pointee(DrawsRectangle(gfx::RectF(0, 0, 300, 200), Color::kBlack)));
  int black_sorting_context_id =
      GetTransformNode(black_layer).sorting_context_id;
  EXPECT_NE(0, black_sorting_context_id);
  EXPECT_NE(light_gray_sorting_context_id, black_sorting_context_id);
}

TEST_P(PaintArtifactCompositorTest, OneClip) {
  auto* clip = CreateClip(c0(), t0(), FloatRoundedRect(100, 100, 300, 200));

  TestPaintArtifact artifact;
  artifact.Chunk(t0(), *clip, e0())
      .RectDrawing(gfx::Rect(220, 80, 300, 200), Color::kBlack);
  Update(artifact.Build());

  ASSERT_EQ(1u, LayerCount());
  const cc::Layer* layer = LayerAt(0);
  // The layer is clipped.
  EXPECT_EQ(gfx::Size(180, 180), layer->bounds());
  EXPECT_EQ(gfx::Vector2dF(220, 100), layer->offset_to_transform_parent());
  EXPECT_THAT(
      layer->GetPicture(),
      Pointee(DrawsRectangle(gfx::RectF(0, 0, 300, 180), Color::kBlack)));
  EXPECT_EQ(Translation(220, 100), layer->ScreenSpaceTransform());

  const cc::ClipNode* clip_node =
      GetPropertyTrees().clip_tree().Node(layer->clip_tree_index());
  EXPECT_TRUE(clip_node->AppliesLocalClip());
  EXPECT_EQ(gfx::RectF(100, 100, 300, 200), clip_node->clip);
}

TEST_P(PaintArtifactCompositorTest, OneClipWithAlias) {
  auto* real_clip =
      CreateClip(c0(), t0(), FloatRoundedRect(100, 100, 300, 200));
  auto* clip = ClipPaintPropertyNodeAlias::Create(*real_clip);

  TestPaintArtifact artifact;
  artifact.Chunk(t0(), *clip, e0())
      .RectDrawing(gfx::Rect(220, 80, 300, 200), Color::kBlack);
  Update(artifact.Build());

  ASSERT_EQ(1u, LayerCount());
  const cc::Layer* layer = LayerAt(0);
  // The layer is clipped.
  EXPECT_EQ(gfx::Size(180, 180), layer->bounds());
  EXPECT_EQ(gfx::Vector2dF(220, 100), layer->offset_to_transform_parent());
  EXPECT_THAT(
      layer->GetPicture(),
      Pointee(DrawsRectangle(gfx::RectF(0, 0, 300, 180), Color::kBlack)));
  EXPECT_EQ(Translation(220, 100), layer->ScreenSpaceTransform());

  const cc::ClipNode* clip_node =
      GetPropertyTrees().clip_tree().Node(layer->clip_tree_index());
  EXPECT_TRUE(clip_node->AppliesLocalClip());
  EXPECT_EQ(gfx::RectF(100, 100, 300, 200), clip_node->clip);
}

TEST_P(PaintArtifactCompositorTest, NestedClips) {
  auto* transform1 = CreateTransform(t0(), gfx::Transform(), gfx::Point3F(),
                                     CompositingReason::kWillChangeTransform);
  auto* clip1 =
      CreateClip(c0(), *transform1, FloatRoundedRect(100, 100, 700, 700));

  auto* transform2 =
      CreateTransform(*transform1, gfx::Transform(), gfx::Point3F(),
                      CompositingReason::kWillChangeTransform);
  auto* clip2 =
      CreateClip(*clip1, *transform2, FloatRoundedRect(200, 200, 700, 700));

  TestPaintArtifact artifact;
  artifact.Chunk(*transform1, *clip1, e0())
      .RectDrawing(gfx::Rect(300, 350, 100, 100), Color::kWhite);
  artifact.Chunk(*transform2, *clip2, e0())
      .RectDrawing(gfx::Rect(300, 350, 100, 100), Color::kLightGray);
  artifact.Chunk(*transform1, *clip1, e0())
      .RectDrawing(gfx::Rect(300, 350, 100, 100), Color::kDarkGray);
  artifact.Chunk(*transform2, *clip2, e0())
      .RectDrawing(gfx::Rect(300, 350, 100, 100), Color::kBlack);
  Update(artifact.Build());

  ASSERT_EQ(4u, LayerCount());

  const cc::Layer* white_layer = LayerAt(0);
  EXPECT_THAT(
      white_layer->GetPicture(),
      Pointee(DrawsRectangle(gfx::RectF(0, 0, 100, 100), Color::kWhite)));
  EXPECT_EQ(Translation(300, 350), white_layer->ScreenSpaceTransform());

  const cc::Layer* light_gray_layer = LayerAt(1);
  EXPECT_THAT(
      light_gray_layer->GetPicture(),
      Pointee(DrawsRectangle(gfx::RectF(0, 0, 100, 100), Color::kLightGray)));
  EXPECT_EQ(Translation(300, 350), light_gray_layer->ScreenSpaceTransform());

  const cc::Layer* dark_gray_layer = LayerAt(2);
  EXPECT_THAT(
      dark_gray_layer->GetPicture(),
      Pointee(DrawsRectangle(gfx::RectF(0, 0, 100, 100), Color::kDarkGray)));
  EXPECT_EQ(Translation(300, 350), dark_gray_layer->ScreenSpaceTransform());

  const cc::Layer* black_layer = LayerAt(3);
  EXPECT_THAT(
      black_layer->GetPicture(),
      Pointee(DrawsRectangle(gfx::RectF(0, 0, 100, 100), Color::kBlack)));
  EXPECT_EQ(Translation(300, 350), black_layer->ScreenSpaceTransform());

  EXPECT_EQ(white_layer->clip_tree_index(), dark_gray_layer->clip_tree_index());
  const cc::ClipNode* outer_clip =
      GetPropertyTrees().clip_tree().Node(white_layer->clip_tree_index());
  EXPECT_TRUE(outer_clip->AppliesLocalClip());
  EXPECT_EQ(gfx::RectF(100, 100, 700, 700), outer_clip->clip);

  EXPECT_EQ(light_gray_layer->clip_tree_index(),
            black_layer->clip_tree_index());
  const cc::ClipNode* inner_clip =
      GetPropertyTrees().clip_tree().Node(black_layer->clip_tree_index());
  EXPECT_TRUE(inner_clip->AppliesLocalClip());
  EXPECT_EQ(gfx::RectF(200, 200, 700, 700), inner_clip->clip);
  EXPECT_EQ(outer_clip->id, inner_clip->parent_id);
}

TEST_P(PaintArtifactCompositorTest, NestedClipsWithAlias) {
  auto* transform1 = CreateTransform(t0(), gfx::Transform(), gfx::Point3F(),
                                     CompositingReason::kWillChangeTransform);
  auto* real_clip1 =
      CreateClip(c0(), *transform1, FloatRoundedRect(100, 100, 700, 700));
  auto* clip1 = ClipPaintPropertyNodeAlias::Create(*real_clip1);
  auto* transform2 =
      CreateTransform(*transform1, gfx::Transform(), gfx::Point3F(),
                      CompositingReason::kWillChangeTransform);
  auto* real_clip2 =
      CreateClip(*clip1, *transform2, FloatRoundedRect(200, 200, 700, 700));
  auto* clip2 = ClipPaintPropertyNodeAlias::Create(*real_clip2);

  TestPaintArtifact artifact;
  artifact.Chunk(*transform1, *clip1, e0())
      .RectDrawing(gfx::Rect(300, 350, 100, 100), Color::kWhite);
  artifact.Chunk(*transform2, *clip2, e0())
      .RectDrawing(gfx::Rect(300, 350, 100, 100), Color::kLightGray);
  artifact.Chunk(*transform1, *clip1, e0())
      .RectDrawing(gfx::Rect(300, 350, 100, 100), Color::kDarkGray);
  artifact.Chunk(*transform2, *clip2, e0())
      .RectDrawing(gfx::Rect(300, 350, 100, 100), Color::kBlack);
  Update(artifact.Build());

  ASSERT_EQ(4u, LayerCount());

  const cc::Layer* white_layer = LayerAt(0);
  EXPECT_THAT(
      white_layer->GetPicture(),
      Pointee(DrawsRectangle(gfx::RectF(0, 0, 100, 100), Color::kWhite)));
  EXPECT_EQ(Translation(300, 350), white_layer->ScreenSpaceTransform());

  const cc::Layer* light_gray_layer = LayerAt(1);
  EXPECT_THAT(
      light_gray_layer->GetPicture(),
      Pointee(DrawsRectangle(gfx::RectF(0, 0, 100, 100), Color::kLightGray)));
  EXPECT_EQ(Translation(300, 350), light_gray_layer->ScreenSpaceTransform());

  const cc::Layer* dark_gray_layer = LayerAt(2);
  EXPECT_THAT(
      dark_gray_layer->GetPicture(),
      Pointee(DrawsRectangle(gfx::RectF(0, 0, 100, 100), Color::kDarkGray)));
  EXPECT_EQ(Translation(300, 350), dark_gray_layer->ScreenSpaceTransform());

  const cc::Layer* black_layer = LayerAt(3);
  EXPECT_THAT(
      black_layer->GetPicture(),
      Pointee(DrawsRectangle(gfx::RectF(0, 0, 100, 100), Color::kBlack)));
  EXPECT_EQ(Translation(300, 350), black_layer->ScreenSpaceTransform());

  EXPECT_EQ(white_layer->clip_tree_index(), dark_gray_layer->clip_tree_index());
  const cc::ClipNode* outer_clip =
      GetPropertyTrees().clip_tree().Node(white_layer->clip_tree_index());
  EXPECT_TRUE(outer_clip->AppliesLocalClip());
  EXPECT_EQ(gfx::RectF(100, 100, 700, 700), outer_clip->clip);

  EXPECT_EQ(light_gray_layer->clip_tree_index(),
            black_layer->clip_tree_index());
  const cc::ClipNode* inner_clip =
      GetPropertyTrees().clip_tree().Node(black_layer->clip_tree_index());
  EXPECT_TRUE(inner_clip->AppliesLocalClip());
  EXPECT_EQ(gfx::RectF(200, 200, 700, 700), inner_clip->clip);
  EXPECT_EQ(outer_clip->id, inner_clip->parent_id);
}

TEST_P(PaintArtifactCompositorTest, DeeplyNestedClips) {
  HeapVector<Member<ClipPaintPropertyNode>> clips;
  for (unsigned i = 1; i <= 10; i++) {
    clips.push_back(CreateClip(clips.empty() ? c0() : *clips.back(), t0(),
                               FloatRoundedRect(5 * i, 0, 100, 200 - 10 * i)));
  }

  TestPain
```