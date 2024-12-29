Response:
My thinking process to analyze the provided C++ code and answer the prompt goes through these stages:

1. **Understand the Goal:** The request asks for the functionality of a specific Chromium Blink engine source file (`compositing_test.cc`), its relation to web technologies (HTML, CSS, JavaScript), examples of logical inference, common usage errors, debugging hints, and a summary of its function (for this first part).

2. **Identify Key Includes and Namespaces:** The `#include` directives reveal the file's dependencies. I scan these for clues about its purpose. I notice includes related to:
    * `base/test/scoped_feature_list.h`:  Suggests testing feature flags.
    * `cc/`:  Indicates interaction with the Chromium Compositor (cc) component, responsible for rendering. Specifically, `cc/layers/`, `cc/trees/`, and `cc/base/features.h` point to layer management, property trees (for optimizations), and compositor feature flags.
    * `testing/gtest/include/gtest/gtest.h`: Confirms this is a test file using the Google Test framework.
    * `third_party/blink/public/common/features.h`: Implies interaction with Blink's feature system.
    * `third_party/blink/renderer/core/`:  Core Blink rendering components: DOM, Frame, Layout, Paint. These are strong indicators of the file's focus.
    * `third_party/blink/renderer/platform/graphics/compositing/`: Directly related to compositing within Blink.
    * `third_party/blink/renderer/platform/testing/`:  Blink-specific testing utilities.

    The `namespace blink {` declaration confirms the scope.

3. **Analyze the `CompositingTest` Class:**  This class, derived from `PaintTestConfigurations` and `testing::Test`, is the central part of the test suite. I look at its members and methods:
    * `SetUp()` and `TearDown()`: Standard testing lifecycle methods for initialization and cleanup. `SetUp` initializes a `WebViewHelper` and sets a preference for compositing LCD text.
    * Helper methods like `InitializeWithHTML`, `LocalMainFrame`, `GetLocalFrameView`, `WebView`, `RootCcLayer`, `CcLayerByDOMElementId`, `LayerTreeHost`, `GetDocument`, `GetElementById`, `GetLayoutObjectById`, `UpdateAllLifecyclePhasesExceptPaint`, `UpdateAllLifecyclePhases`, `GetPropertyTrees`, `GetTransformNode`, `paint_artifact_compositor`: These are utility methods for setting up test scenarios, accessing various Blink and cc objects, and controlling the rendering pipeline lifecycle. The presence of `CcLayer...` methods strongly suggests the tests are verifying the creation and properties of compositor layers.
    * The `INSTANTIATE_PAINT_TEST_SUITE_P(CompositingTest);` line indicates that these tests are parameterized, likely running with different configurations.

4. **Examine Individual `TEST_P` Functions:** Each `TEST_P` function represents a specific test case. I briefly read through the names and the code within each test to understand what aspect of compositing is being tested:
    * `DisableAndEnableAcceleratedCompositing`: Checks enabling/disabling the compositor.
    * `DidScrollCallbackAfterScrollableAreaChanges`: Verifies scroll event handling and layer management when scrollability changes.
    * `FrameViewScroll`: Tests scrolling of the main frame's view.
    * `WillChangeTransformHint`: Checks if `will-change: transform` creates a composited layer with the correct flag.
    * Tests related to SVG (`WillChangeTransformHintInSVG`, `Compositing3DTransformOnSVGModelObject`, etc.):  Focus on how compositing behaves with SVG elements and transformations.
    * `PaintPropertiesWhenCompositingSVG`: Verifies the correct propagation of paint properties (like opacity) to compositor nodes for SVG.
    * `BackgroundColorInScrollingContentsLayer` and `BackgroundColorInGraphicsLayer`: Test background color handling in different compositing scenarios.
    * `ContainPaintLayerBounds`: Checks the effect of `contain: paint`.
    * Tests with "crbug.com" in the name (e.g., `CompositedOverlayScrollbarUnderNonFastBorderRadius`): These are likely regression tests for specific bugs.
    * Tests related to `HitTestOpaqueness`: Focus on how the compositor determines the opaqueness of layers for hit testing.

5. **Identify Relationships to Web Technologies:** Based on the included headers and the test names/logic, I identify clear connections:
    * **HTML:** The tests use `InitializeWithHTML` to set up the DOM structure. Element IDs are used to locate specific elements for testing. HTML attributes (like `style`, `overflow`, `will-change`) are manipulated.
    * **CSS:** CSS properties (like `transform`, `opacity`, `background-color`, `border-radius`, `overflow`, `will-change`, `contain`, `pointer-events`, `backdrop-filter`) are central to triggering compositing and influencing layer properties.
    * **JavaScript:** `LocalMainFrame()->ExecuteScript` is used to trigger layout updates. The tests implicitly check how JavaScript interactions affect compositing.

6. **Infer Logical Relationships (Hypothetical Input/Output):** For tests like `WillChangeTransformHint`, I can infer:
    * **Input:** HTML containing an element with `style="will-change: transform"`.
    * **Output:** The corresponding compositor layer (`CcLayerByDOMElementId`) will have its transform node's `will_change_transform` flag set to `true`.

7. **Consider Common Usage Errors:**  While this is a *test* file, I can think about how the concepts being tested relate to developer errors:
    * Incorrectly using `will-change` (e.g., applying it unnecessarily, leading to performance issues).
    * Not understanding how CSS properties trigger compositing, leading to unexpected layer creation or missing optimizations.
    * Issues with z-indexing and stacking contexts when compositing isn't properly understood.

8. **Trace User Actions to Code (Debugging Hints):** I consider how a user action might lead to this code being relevant during debugging:
    * A user scrolls a page. This triggers scroll events, potentially leading to the execution paths tested in `DidScrollCallbackAfterScrollableAreaChanges` and `FrameViewScroll`.
    * A user interacts with an element that has a CSS animation or transition involving `transform` or `opacity`. This would involve the compositing logic tested here.
    * A developer inspects the rendering layers in DevTools, and understanding how the compositor creates and manages layers (as tested here) is crucial for debugging rendering issues.

9. **Summarize the Functionality (Part 1):**  Based on the analysis, I synthesize a concise summary of the file's purpose.

By following these steps, I can systematically break down the code, understand its purpose within the larger Chromium/Blink project, and address the specific points raised in the prompt. The key is to leverage the information provided by the code itself (includes, class names, method names, test names) to infer its functionality and relationships to other components and web technologies.
好的，我们来分析一下 `blink/renderer/core/paint/compositing/compositing_test.cc` 文件的功能。

**文件功能归纳：**

这个 C++ 文件是 Chromium Blink 引擎中负责 **测试合成（Compositing）机制** 的单元测试文件。它的主要功能是：

1. **验证 Blink 渲染引擎的布局、绘制信息能否正确地传递给 Chromium 合成器 (Compositor, cc 命名空间下的组件)。**  合成器负责将不同的渲染层合并成最终的屏幕图像。
2. **测试在不同的 HTML、CSS 场景下，Blink 是否能正确地创建和管理合成层。** 例如，哪些 CSS 属性会触发元素变成合成层，合成层的属性（如变换、透明度、滚动等）是否正确。
3. **验证合成相关的回调函数和事件是否按预期工作。** 例如，滚动事件发生后，合成层是否能正确接收到滚动偏移量的信息。
4. **测试一些特定的合成优化和特性。** 例如，`will-change` 属性对合成的影响，`contain: paint` 属性的作用，以及命中测试不透明度（HitTestOpaqueness）的计算。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

这个测试文件直接关联到 HTML、CSS，并通过模拟用户操作或脚本执行来间接涉及 JavaScript。

* **HTML:** 测试用例通过 `InitializeWithHTML` 方法加载 HTML 代码片段，构建 DOM 树。这些 HTML 代码定义了被测试的元素及其结构。
    * **举例:**  在测试 `WillChangeTransformHint` 中，HTML 代码 `<div id="willChange" style="width: 100px; height: 100px; will-change: transform; background: blue;"></div>` 创建了一个 div 元素，并使用 `will-change: transform` 属性，测试会验证这个属性是否正确地触发了合成。

* **CSS:** 测试用例使用 CSS 样式来控制元素的渲染属性，这些属性是触发合成的关键因素。
    * **举例:**
        * `transform: translate3d(0, 0, 1px)`:  测试 `Compositing3DTransformOnSVGModelObject` 中，通过 CSS 的 3D 变换来触发 SVG 元素的合成。
        * `opacity: 0.9`: 测试 `PaintPropertiesWhenCompositingSVG` 中，验证 CSS 的 `opacity` 属性是否正确传递到合成层的效果节点。
        * `overflow: scroll`: 测试 `DidScrollCallbackAfterScrollableAreaChanges` 和 `FrameViewScroll` 中，验证滚动容器的合成和滚动事件处理。
        * `pointer-events: none`: 测试 `HitTestOpaqueness` 中，验证 CSS 的 `pointer-events` 属性如何影响合成层的命中测试不透明度。

* **JavaScript:**  虽然这个测试文件主要是 C++ 代码，但它会通过 Blink 的内部机制来模拟 JavaScript 的影响，例如：
    * **触发布局更新:**  `LocalMainFrame()->ExecuteScript(WebScriptSource("var forceLayoutFromScript = scrollable.offsetTop;"));` 这行代码会执行 JavaScript，强制进行布局计算，测试在布局更新后合成状态的变化。
    * **模拟滚动行为:**  `GetElementById("scroll")->scrollTo(0, 2);` 这行代码模拟 JavaScript 调用 `scrollTo` 方法，测试滚动后合成状态的更新。

**逻辑推理与假设输入输出：**

以 `WillChangeTransformHint` 测试为例：

* **假设输入:**  一个 HTML 字符串，其中包含一个 ID 为 "willChange" 的 `div` 元素，并且该元素具有 CSS 属性 `will-change: transform;`。
* **逻辑推理:**  `will-change: transform` 属性是 Blink 中触发元素变成合成层的因素之一。因此，当渲染引擎处理这个元素时，应该会创建一个对应的合成层，并且该合成层的变换节点 (TransformNode) 的 `will_change_transform` 标志应该被设置为 true。
* **预期输出:**  `GetTransformNode(layer)->will_change_transform` 的值为 `true`。

**用户或编程常见的使用错误举例：**

虽然这是测试代码，但它反映了开发者在使用 HTML 和 CSS 时可能遇到的问题：

* **过度使用 `will-change`:** 开发者可能会为了“优化”性能而对很多元素都使用 `will-change`，但实际上这可能会导致过多的合成层，反而降低性能。这个测试文件验证了 `will-change` 的基本功能，帮助理解其作用范围。
* **不理解哪些 CSS 属性会触发合成:** 开发者可能不清楚哪些 CSS 属性会导致元素变成合成层。例如，他们可能意外地使用了某个属性，导致不必要的合成层创建。这个测试文件覆盖了多种触发合成的 CSS 属性，有助于开发者理解这些规则。
* **滚动相关的问题:**  开发者在处理滚动时，可能会遇到合成层滚动不正常或者滚动事件处理错误的问题。`DidScrollCallbackAfterScrollableAreaChanges` 和 `FrameViewScroll` 这类测试有助于发现和修复这些问题。

**用户操作如何一步步到达这里 (调试线索)：**

作为一个开发人员，当你遇到与页面渲染、动画、滚动或者性能相关的问题时，可能会需要查看合成相关的代码。以下是一些可能的步骤：

1. **用户操作触发渲染问题:** 用户在浏览器中进行操作，例如滚动页面、触发动画、或者与使用了特定 CSS 属性的元素交互，导致页面渲染出现异常或者性能下降。
2. **开发者工具分析:**  开发者使用 Chrome 的开发者工具 (DevTools) 中的 "Layers" 面板来查看页面的合成层结构，发现某些元素的合成状态不符合预期。
3. **查找相关代码:** 开发者可能会根据 DevTools 的信息，或者相关的错误信息，定位到 Blink 渲染引擎中负责合成逻辑的代码。
4. **查看测试用例:** 为了理解合成机制的具体实现和规则，开发者可能会查看相关的单元测试，例如 `compositing_test.cc`，来了解特定 CSS 属性或场景下，合成器是如何工作的。
5. **调试代码:** 如果需要深入了解，开发者可能会设置断点，单步调试 `compositing_test.cc` 中的测试用例，观察 Blink 和 Compositor 之间的交互过程。

**本部分功能归纳：**

`blink/renderer/core/paint/compositing/compositing_test.cc` 的这第一部分主要定义了一个名为 `CompositingTest` 的测试类，并包含了一些基础的测试用例，用于验证：

* **启用和禁用硬件加速合成的能力。**
* **滚动容器的合成和滚动事件处理，包括滚动区域变化时的处理。**
* **`will-change: transform` 属性对元素合成的影响，以及在 SVG 元素上的特定行为。**
* **3D 变换对 SVG 元素合成的影响。**
* **在 SVG 合成场景下，绘制属性（如透明度）的传递。**
* **不同背景绘制模式下，合成层的背景色设置。**
* **`contain: paint` 属性对合成层边界的影响。**
* **在特定场景下，合成覆盖滚动条的处理。**
* **由于滚动导致的合成更新。**
* **不同场景下，合成层的命中测试不透明度 (HitTestOpaqueness) 的计算。**

总而言之，这部分代码建立了一个测试框架，并开始覆盖一些核心的合成功能点，确保 Blink 能够正确地将渲染信息传递给合成器，并按照预期创建和管理合成层。

Prompt: 
```
这是目录为blink/renderer/core/paint/compositing/compositing_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共5部分，请归纳一下它的功能

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/containers/span.h"
#include "base/test/scoped_feature_list.h"
#include "build/build_config.h"
#include "cc/base/features.h"
#include "cc/layers/picture_layer.h"
#include "cc/layers/recording_source.h"
#include "cc/layers/surface_layer.h"
#include "cc/trees/compositor_commit_data.h"
#include "cc/trees/effect_node.h"
#include "cc/trees/layer_tree_host.h"
#include "cc/trees/scroll_node.h"
#include "cc/trees/transform_node.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/web/web_script_source.h"
#include "third_party/blink/renderer/core/dom/dom_node_ids.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html/html_iframe_element.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/svg_names.h"
#include "third_party/blink/renderer/core/testing/fake_remote_frame_host.h"
#include "third_party/blink/renderer/core/testing/scoped_mock_overlay_scrollbars.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/graphics/compositing/paint_artifact_compositor.h"
#include "third_party/blink/renderer/platform/testing/find_cc_layer.h"
#include "third_party/blink/renderer/platform/testing/paint_test_configurations.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/text/base64.h"

namespace blink {

#define EXPECT_SKCOLOR4F_NEAR(expected, actual, error) \
  do {                                                 \
    EXPECT_NEAR(expected.fR, actual.fR, error);        \
    EXPECT_NEAR(expected.fG, actual.fG, error);        \
    EXPECT_NEAR(expected.fB, actual.fB, error);        \
    EXPECT_NEAR(expected.fA, actual.fA, error);        \
  } while (false)

// Tests the integration between blink and cc where a layer list is sent to cc.
class CompositingTest : public PaintTestConfigurations, public testing::Test {
 public:
  void SetUp() override {
    web_view_helper_ = std::make_unique<frame_test_helpers::WebViewHelper>();
    web_view_helper_->Initialize();
    GetLocalFrameView()
        ->GetFrame()
        .GetSettings()
        ->SetPreferCompositingToLCDTextForTesting(true);
    web_view_helper_->Resize(gfx::Size(200, 200));
  }

  void TearDown() override { web_view_helper_.reset(); }

  // Both sets the inner html and runs the document lifecycle.
  void InitializeWithHTML(LocalFrame& frame, const String& html_content) {
    frame.GetDocument()->body()->setInnerHTML(html_content);
    frame.GetDocument()->View()->UpdateAllLifecyclePhasesForTest();
  }

  WebLocalFrame* LocalMainFrame() { return web_view_helper_->LocalMainFrame(); }

  LocalFrameView* GetLocalFrameView() {
    return web_view_helper_->LocalMainFrame()->GetFrameView();
  }

  WebViewImpl* WebView() { return web_view_helper_->GetWebView(); }

  cc::Layer* RootCcLayer() { return paint_artifact_compositor()->RootLayer(); }

  cc::Layer* CcLayerByDOMElementId(const char* id) {
    auto layers = CcLayersByDOMElementId(RootCcLayer(), id);
    return layers.empty() ? nullptr : layers[0];
  }

  cc::LayerTreeHost* LayerTreeHost() {
    return web_view_helper_->LocalMainFrame()
        ->FrameWidgetImpl()
        ->LayerTreeHostForTesting();
  }

  Document& GetDocument() {
    return *GetLocalFrameView()->GetFrame().GetDocument();
  }

  Element* GetElementById(const char* id) {
    return GetDocument().getElementById(AtomicString(id));
  }

  LayoutObject* GetLayoutObjectById(const char* id) {
    return GetElementById(id)->GetLayoutObject();
  }

  void UpdateAllLifecyclePhasesExceptPaint() {
    GetLocalFrameView()->UpdateAllLifecyclePhasesExceptPaint(
        DocumentUpdateReason::kTest);
  }

  void UpdateAllLifecyclePhases() {
    WebView()->MainFrameWidget()->UpdateAllLifecyclePhases(
        DocumentUpdateReason::kTest);
  }

  cc::PropertyTrees* GetPropertyTrees() {
    return LayerTreeHost()->property_trees();
  }

  cc::TransformNode* GetTransformNode(const cc::Layer* layer) {
    return GetPropertyTrees()->transform_tree_mutable().Node(
        layer->transform_tree_index());
  }

  PaintArtifactCompositor* paint_artifact_compositor() {
    return GetLocalFrameView()->GetPaintArtifactCompositor();
  }

 private:
  std::unique_ptr<frame_test_helpers::WebViewHelper> web_view_helper_;

  test::TaskEnvironment task_environment_;
};

INSTANTIATE_PAINT_TEST_SUITE_P(CompositingTest);

TEST_P(CompositingTest, DisableAndEnableAcceleratedCompositing) {
  UpdateAllLifecyclePhases();
  auto* settings = GetLocalFrameView()->GetFrame().GetSettings();
  size_t num_layers = RootCcLayer()->children().size();
  EXPECT_GT(num_layers, 1u);
  settings->SetAcceleratedCompositingEnabled(false);
  UpdateAllLifecyclePhases();
  EXPECT_FALSE(paint_artifact_compositor());
  settings->SetAcceleratedCompositingEnabled(true);
  UpdateAllLifecyclePhases();
  EXPECT_EQ(num_layers, RootCcLayer()->children().size());
}

TEST_P(CompositingTest, DidScrollCallbackAfterScrollableAreaChanges) {
  InitializeWithHTML(*WebView()->MainFrameImpl()->GetFrame(),
                     "<style>"
                     "  #scrollable {"
                     "    height: 100px;"
                     "    width: 100px;"
                     "    overflow: scroll;"
                     "    will-change: transform;"
                     "  }"
                     "  #forceScroll { height: 120px; width: 50px; }"
                     "</style>"
                     "<div id='scrollable'>"
                     "  <div id='forceScroll'></div>"
                     "</div>");

  UpdateAllLifecyclePhases();

  Document* document = WebView()->MainFrameImpl()->GetFrame()->GetDocument();
  Element* scrollable = document->getElementById(AtomicString("scrollable"));

  auto* scrollable_area = scrollable->GetLayoutBox()->GetScrollableArea();
  EXPECT_NE(nullptr, scrollable_area);

  CompositorElementId scroll_element_id = scrollable_area->GetScrollElementId();
  auto* overflow_scroll_layer =
      CcLayerByCcElementId(RootCcLayer(), scroll_element_id);
  const auto* scroll_node = RootCcLayer()
                                ->layer_tree_host()
                                ->property_trees()
                                ->scroll_tree()
                                .FindNodeFromElementId(scroll_element_id);
  EXPECT_EQ(scroll_node->container_bounds, gfx::Size(100, 100));

  // Ensure a synthetic impl-side scroll offset propagates to the scrollable
  // area using the DidScroll callback.
  EXPECT_EQ(ScrollOffset(), scrollable_area->GetScrollOffset());
  cc::CompositorCommitData commit_data;
  commit_data.scrolls.push_back(
      {scroll_element_id, gfx::Vector2dF(0, 1), std::nullopt});
  overflow_scroll_layer->layer_tree_host()->ApplyCompositorChanges(
      &commit_data);
  UpdateAllLifecyclePhases();
  EXPECT_EQ(ScrollOffset(0, 1), scrollable_area->GetScrollOffset());

  // Make the scrollable area non-scrollable.
  scrollable->setAttribute(html_names::kStyleAttr,
                           AtomicString("overflow: visible"));

  // Update layout without updating compositing state.
  LocalMainFrame()->ExecuteScript(
      WebScriptSource("var forceLayoutFromScript = scrollable.offsetTop;"));
  EXPECT_EQ(document->Lifecycle().GetState(), DocumentLifecycle::kLayoutClean);

  EXPECT_EQ(nullptr, scrollable->GetLayoutBox()->GetScrollableArea());

  // The web scroll layer has not been deleted yet and we should be able to
  // apply impl-side offsets without crashing.
  ASSERT_EQ(overflow_scroll_layer,
            CcLayerByCcElementId(RootCcLayer(), scroll_element_id));
  commit_data.scrolls[0] = {scroll_element_id, gfx::Vector2dF(0, 1),
                            std::nullopt};
  overflow_scroll_layer->layer_tree_host()->ApplyCompositorChanges(
      &commit_data);

  UpdateAllLifecyclePhases();
  EXPECT_FALSE(CcLayerByCcElementId(RootCcLayer(), scroll_element_id));
}

TEST_P(CompositingTest, FrameViewScroll) {
  InitializeWithHTML(*WebView()->MainFrameImpl()->GetFrame(),
                     "<style>"
                     "  #forceScroll {"
                     "    height: 2000px;"
                     "    width: 100px;"
                     "  }"
                     "</style>"
                     "<div id='forceScroll'></div>");

  UpdateAllLifecyclePhases();

  auto* scrollable_area = GetLocalFrameView()->LayoutViewport();
  EXPECT_NE(nullptr, scrollable_area);

  const auto* scroll_node =
      RootCcLayer()
          ->layer_tree_host()
          ->property_trees()
          ->scroll_tree()
          .FindNodeFromElementId(scrollable_area->GetScrollElementId());
  ASSERT_TRUE(scroll_node);

  // Ensure a synthetic impl-side scroll offset propagates to the scrollable
  // area using the DidScroll callback.
  EXPECT_EQ(ScrollOffset(), scrollable_area->GetScrollOffset());
  cc::CompositorCommitData commit_data;
  commit_data.scrolls.push_back({scrollable_area->GetScrollElementId(),
                                 gfx::Vector2dF(0, 1), std::nullopt});
  RootCcLayer()->layer_tree_host()->ApplyCompositorChanges(&commit_data);
  UpdateAllLifecyclePhases();
  EXPECT_EQ(ScrollOffset(0, 1), scrollable_area->GetScrollOffset());
}

TEST_P(CompositingTest, WillChangeTransformHint) {
  InitializeWithHTML(*WebView()->MainFrameImpl()->GetFrame(), R"HTML(
    <style>
      #willChange {
        width: 100px;
        height: 100px;
        will-change: transform;
        background: blue;
      }
    </style>
    <div id="willChange"></div>
  )HTML");
  UpdateAllLifecyclePhases();
  auto* layer = CcLayerByDOMElementId("willChange");
  auto* transform_node = GetTransformNode(layer);
  EXPECT_TRUE(transform_node->will_change_transform);
}

TEST_P(CompositingTest, WillChangeTransformHintInSVG) {
  InitializeWithHTML(*WebView()->MainFrameImpl()->GetFrame(), R"HTML(
    <!doctype html>
    <style>
      #willChange {
        width: 100px;
        height: 100px;
        will-change: transform;
      }
    </style>
    <svg width="200" height="200">
      <rect id="willChange" fill="blue"></rect>
    </svg>
  )HTML");
  UpdateAllLifecyclePhases();
  auto* layer = CcLayerByDOMElementId("willChange");
  auto* transform_node = GetTransformNode(layer);
  // For now will-change:transform triggers compositing for SVG, but we don't
  // pass the flag to cc to ensure raster quality.
  EXPECT_FALSE(transform_node->will_change_transform);
}

TEST_P(CompositingTest, Compositing3DTransformOnSVGModelObject) {
  InitializeWithHTML(*WebView()->MainFrameImpl()->GetFrame(), R"HTML(
    <!doctype html>
    <svg width="200" height="200">
      <rect id="target" fill="blue" width="100" height="100"></rect>
    </svg>
  )HTML");
  UpdateAllLifecyclePhases();
  EXPECT_FALSE(CcLayerByDOMElementId("target"));

  // Adding a 3D transform should trigger compositing.
  auto* target_element = GetElementById("target");
  target_element->setAttribute(
      html_names::kStyleAttr,
      AtomicString("transform: translate3d(0, 0, 1px)"));
  UpdateAllLifecyclePhases();
  // |HasTransformRelatedProperty| is used in |CompositingReasonsFor3DTransform|
  // and must be set correctly.
  ASSERT_TRUE(GetLayoutObjectById("target")->HasTransformRelatedProperty());
  EXPECT_TRUE(CcLayerByDOMElementId("target"));

  // Removing a 3D transform removes the compositing trigger.
  target_element->setAttribute(html_names::kStyleAttr,
                               AtomicString("transform: none"));
  UpdateAllLifecyclePhases();
  // |HasTransformRelatedProperty| is used in |CompositingReasonsFor3DTransform|
  // and must be set correctly.
  ASSERT_FALSE(GetLayoutObjectById("target")->HasTransformRelatedProperty());
  EXPECT_FALSE(CcLayerByDOMElementId("target"));

  // Adding a 2D transform should not trigger compositing.
  target_element->setAttribute(html_names::kStyleAttr,
                               AtomicString("transform: translate(1px, 0)"));
  UpdateAllLifecyclePhases();
  EXPECT_FALSE(CcLayerByDOMElementId("target"));

  // Switching from a 2D to a 3D transform should trigger compositing.
  target_element->setAttribute(
      html_names::kStyleAttr,
      AtomicString("transform: translate3d(0, 0, 1px)"));
  UpdateAllLifecyclePhases();
  EXPECT_TRUE(CcLayerByDOMElementId("target"));
}

TEST_P(CompositingTest, Compositing3DTransformOnSVGBlock) {
  InitializeWithHTML(*WebView()->MainFrameImpl()->GetFrame(), R"HTML(
    <!doctype html>
    <svg width="200" height="200">
      <text id="target" x="50" y="50">text</text>
    </svg>
  )HTML");
  UpdateAllLifecyclePhases();
  EXPECT_FALSE(CcLayerByDOMElementId("target"));

  // Adding a 3D transform should trigger compositing.
  auto* target_element = GetElementById("target");
  target_element->setAttribute(
      html_names::kStyleAttr,
      AtomicString("transform: translate3d(0, 0, 1px)"));
  UpdateAllLifecyclePhases();
  // |HasTransformRelatedProperty| is used in |CompositingReasonsFor3DTransform|
  // and must be set correctly.
  ASSERT_TRUE(GetLayoutObjectById("target")->HasTransformRelatedProperty());
  EXPECT_TRUE(CcLayerByDOMElementId("target"));

  // Removing a 3D transform removes the compositing trigger.
  target_element->setAttribute(html_names::kStyleAttr,
                               AtomicString("transform: none"));
  UpdateAllLifecyclePhases();
  // |HasTransformRelatedProperty| is used in |CompositingReasonsFor3DTransform|
  // and must be set correctly.
  ASSERT_FALSE(GetLayoutObjectById("target")->HasTransformRelatedProperty());
  EXPECT_FALSE(CcLayerByDOMElementId("target"));

  // Adding a 2D transform should not trigger compositing.
  target_element->setAttribute(html_names::kStyleAttr,
                               AtomicString("transform: translate(1px, 0)"));
  UpdateAllLifecyclePhases();
  EXPECT_FALSE(CcLayerByDOMElementId("target"));

  // Switching from a 2D to a 3D transform should trigger compositing.
  target_element->setAttribute(
      html_names::kStyleAttr,
      AtomicString("transform: translate3d(0, 0, 1px)"));
  UpdateAllLifecyclePhases();
  EXPECT_TRUE(CcLayerByDOMElementId("target"));
}

// Inlines do not support the transform property and should not be composited
// due to 3D transforms.
TEST_P(CompositingTest, NotCompositing3DTransformOnSVGInline) {
  InitializeWithHTML(*WebView()->MainFrameImpl()->GetFrame(), R"HTML(
    <!doctype html>
    <svg width="200" height="200">
      <text x="50" y="50">
        text
        <tspan id="inline">tspan</tspan>
      </text>
    </svg>
  )HTML");
  UpdateAllLifecyclePhases();
  EXPECT_FALSE(CcLayerByDOMElementId("inline"));

  // Adding a 3D transform to an inline should not trigger compositing.
  auto* inline_element = GetElementById("inline");
  inline_element->setAttribute(
      html_names::kStyleAttr,
      AtomicString("transform: translate3d(0, 0, 1px)"));
  UpdateAllLifecyclePhases();
  // |HasTransformRelatedProperty| is used in |CompositingReasonsFor3DTransform|
  // and must be set correctly.
  ASSERT_FALSE(GetLayoutObjectById("inline")->HasTransformRelatedProperty());
  EXPECT_FALSE(CcLayerByDOMElementId("inline"));
}

TEST_P(CompositingTest, PaintPropertiesWhenCompositingSVG) {
  InitializeWithHTML(*WebView()->MainFrameImpl()->GetFrame(), R"HTML(
    <!doctype html>
    <style>
      #ancestor {
        opacity: 0.9;
      }
      #svg {
        opacity: 0.8;
      }
      #rect {
        width: 100px;
        height: 100px;
        will-change: transform;
        opacity: 0.7;
      }
    </style>
    <div id="ancestor">
      <svg id="svg" width="200" height="200">
        <rect width="10" height="10" fill="red"></rect>
        <rect id="rect" fill="blue" stroke-width="1" stroke="black"></rect>
      </svg>
    </div>
  )HTML");
  UpdateAllLifecyclePhases();
  auto* ancestor = CcLayerByDOMElementId("ancestor");
  auto* ancestor_effect_node = GetPropertyTrees()->effect_tree_mutable().Node(
      ancestor->effect_tree_index());
  EXPECT_EQ(ancestor_effect_node->opacity, 0.9f);

  auto* svg_root = CcLayerByDOMElementId("svg");
  const auto* svg_root_effect_node =
      GetPropertyTrees()->effect_tree().Node(svg_root->effect_tree_index());
  EXPECT_EQ(svg_root_effect_node->opacity, 0.8f);
  EXPECT_EQ(svg_root_effect_node->parent_id, ancestor_effect_node->id);

  auto* rect = CcLayerByDOMElementId("rect");
  const auto* rect_effect_node =
      GetPropertyTrees()->effect_tree().Node(rect->effect_tree_index());

  EXPECT_EQ(rect_effect_node->opacity, 0.7f);
  EXPECT_EQ(rect_effect_node->parent_id, svg_root_effect_node->id);
}

TEST_P(CompositingTest, BackgroundColorInScrollingContentsLayer) {
  InitializeWithHTML(*WebView()->MainFrameImpl()->GetFrame(), R"HTML(
    <style>
      html {
        background-color: rgb(10, 20, 30);
      }
      #scroller {
        will-change: transform;
        overflow: scroll;
        height: 100px;
        width: 100px;
        background-color: rgb(30, 40, 50);
      }
      .spacer {
        height: 1000px;
      }
    </style>
    <div id="scroller">
      <div class="spacer"></div>
    </div>
    <div class="spacer"></div>
  )HTML");
  UpdateAllLifecyclePhases();

  LayoutView* layout_view = GetLocalFrameView()->GetLayoutView();
  Element* scroller = GetElementById("scroller");
  LayoutBox* scroller_box = scroller->GetLayoutBox();
  ASSERT_TRUE(layout_view->GetBackgroundPaintLocation() ==
              kBackgroundPaintInContentsSpace);
  ASSERT_TRUE(scroller_box->GetBackgroundPaintLocation() ==
              kBackgroundPaintInContentsSpace);

  // The root layer and root scrolling contents layer get background_color by
  // blending the CSS background-color of the <html> element with
  // LocalFrameView::BaseBackgroundColor(), which is white by default.
  auto* layer = CcLayersByName(RootCcLayer(), "LayoutView #document")[0];
  SkColor4f expected_color = SkColor4f::FromColor(SkColorSetRGB(10, 20, 30));
  EXPECT_EQ(layer->background_color(), SkColors::kTransparent);
  auto* scrollable_area = GetLocalFrameView()->LayoutViewport();
  layer = ScrollingContentsCcLayerByScrollElementId(
      RootCcLayer(), scrollable_area->GetScrollElementId());
  EXPECT_SKCOLOR4F_NEAR(layer->background_color(), expected_color, 0.005f);

  // Non-root layers set background_color based on the CSS background color of
  // the layer-defining element.
  expected_color = SkColor4f::FromColor(SkColorSetRGB(30, 40, 50));
  layer = CcLayerByDOMElementId("scroller");
  EXPECT_EQ(layer->background_color(), SkColors::kTransparent);
  scrollable_area = scroller_box->GetScrollableArea();
  layer = ScrollingContentsCcLayerByScrollElementId(
      RootCcLayer(), scrollable_area->GetScrollElementId());
  EXPECT_SKCOLOR4F_NEAR(layer->background_color(), expected_color, 0.005f);
}

TEST_P(CompositingTest, BackgroundColorInGraphicsLayer) {
  InitializeWithHTML(*WebView()->MainFrameImpl()->GetFrame(), R"HTML(
    <style>
      html {
        background-image: linear-gradient(rgb(10, 20, 30), rgb(60, 70, 80));
        background-attachment: fixed;
      }
      #scroller {
        will-change: transform;
        overflow: scroll;
        height: 100px;
        width: 100px;
        background-color: rgba(30, 40, 50, .6);
        background-clip: content-box;
        background-attachment: scroll;
        padding: 1px;
      }
      .spacer {
        height: 1000px;
      }
    </style>
    <div id="scroller">
      <div class="spacer"></div>
    </div>
    <div class="spacer"></div>
  )HTML");
  UpdateAllLifecyclePhases();

  LayoutView* layout_view = GetLocalFrameView()->GetLayoutView();
  Element* scroller = GetElementById("scroller");
  LayoutBox* scroller_box = scroller->GetLayoutBox();
  ASSERT_TRUE(layout_view->GetBackgroundPaintLocation() ==
              kBackgroundPaintInBorderBoxSpace);
  ASSERT_TRUE(scroller_box->GetBackgroundPaintLocation() ==
              kBackgroundPaintInBorderBoxSpace);

  // The root layer gets background_color by blending the CSS background-color
  // of the <html> element with LocalFrameView::BaseBackgroundColor(), which is
  // white by default. In this case, because the background is a gradient, it
  // will blend transparent with white, resulting in white. Because the
  // background is painted into the root graphics layer, the root scrolling
  // contents layer should not checkerboard, so its background color should be
  // transparent.
  auto* layer = CcLayersByName(RootCcLayer(), "LayoutView #document")[0];
  EXPECT_EQ(layer->background_color(), SkColors::kWhite);
  auto* scrollable_area = GetLocalFrameView()->LayoutViewport();
  layer = ScrollingContentsCcLayerByScrollElementId(
      RootCcLayer(), scrollable_area->GetScrollElementId());
  EXPECT_EQ(layer->background_color(), SkColors::kTransparent);
  EXPECT_EQ(layer->SafeOpaqueBackgroundColor(), SkColors::kTransparent);

  // Non-root layers set background_color based on the CSS background color of
  // the layer-defining element.
  SkColor4f expected_color =
      SkColor4f::FromColor(SkColorSetARGB(roundf(255. * 0.6), 30, 40, 50));
  layer = CcLayerByDOMElementId("scroller");
  EXPECT_SKCOLOR4F_NEAR(layer->background_color(), expected_color, 0.005f);
  scrollable_area = scroller_box->GetScrollableArea();
  layer = ScrollingContentsCcLayerByScrollElementId(
      RootCcLayer(), scrollable_area->GetScrollElementId());
  EXPECT_EQ(layer->background_color(), SkColors::kTransparent);
  EXPECT_EQ(layer->SafeOpaqueBackgroundColor(), SkColors::kTransparent);
}

TEST_P(CompositingTest, ContainPaintLayerBounds) {
  InitializeWithHTML(*WebView()->MainFrameImpl()->GetFrame(), R"HTML(
    <div id="target" style="will-change: transform; contain: paint;
                            width: 200px; height: 100px">
      <div style="width: 300px; height: 400px"></div>
    </div>
  )HTML");

  UpdateAllLifecyclePhases();
  auto* layer = CcLayersByDOMElementId(RootCcLayer(), "target")[0];
  ASSERT_TRUE(layer);
  EXPECT_EQ(gfx::Size(200, 100), layer->bounds());
}

// https://crbug.com/1422877:
TEST_P(CompositingTest, CompositedOverlayScrollbarUnderNonFastBorderRadius) {
  ScopedMockOverlayScrollbars mock_overlay_scrollbars;

  InitializeWithHTML(*WebView()->MainFrameImpl()->GetFrame(), R"HTML(
    <div id="rounded" style="width: 150px; height: 150px;
                             border-radius: 10px / 20px; overflow: hidden;
                             will-change: opacity">
      Content1
      <div id="scroll1" style="width: 100px; height: 100px; overflow: scroll">
        <div style="height: 2000px">Content2</div>
      </div>
      Content3
      <div id="scroll2" style="width: 100px; height: 100px; overflow: scroll">
        <div style="height: 2000px">Content4</div>
      </div>
      Content5
    </div>
  )HTML");
  UpdateAllLifecyclePhases();

  ASSERT_TRUE(GetLayoutObjectById("scroll1")
                  ->FirstFragment()
                  .PaintProperties()
                  ->VerticalScrollbarEffect());
  EXPECT_EQ(1u, CcLayersByName(RootCcLayer(), "Synthesized Clip").size());
}

// https://crbug.com/1459318
TEST_P(CompositingTest,
       FullPACUpdateOnScrollWithSyntheticClipAcrossScrollerSimpleRadius) {
  InitializeWithHTML(*WebView()->MainFrameImpl()->GetFrame(), R"HTML(
    <div id="scroll" style="width: 200px; height: 200px;
                            border-radius: 2px;
                            overflow: scroll; background: white">
      <div id="masked" style="width: 100px; height: 100px;
                              backdrop-filter: blur(1px)"></div>
      <div style="height: 200px"></div>
    </div>
  )HTML");

  EXPECT_FALSE(paint_artifact_compositor()->NeedsUpdate());
  GetElementById("scroll")->scrollTo(0, 2);
  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_TRUE(paint_artifact_compositor()->NeedsUpdate());
  UpdateAllLifecyclePhases();
}

// https://crbug.com/1459318
TEST_P(CompositingTest,
       FullPACUpdateOnScrollWithSyntheticClipAcrossScrollerComplexRadius) {
  InitializeWithHTML(*WebView()->MainFrameImpl()->GetFrame(), R"HTML(
    <div id="scroll" style="width: 200px; height: 200px;
                            border-radius: 2px / 4px;
                            overflow: scroll; background: white">
      <div id="masked" style="width: 100px; height: 100px;
                              backdrop-filter: blur(1px)"></div>
      <div style="height: 200px"></div>
    </div>
  )HTML");

  EXPECT_FALSE(paint_artifact_compositor()->NeedsUpdate());
  GetElementById("scroll")->scrollTo(0, 2);
  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_TRUE(paint_artifact_compositor()->NeedsUpdate());
  UpdateAllLifecyclePhases();
}

TEST_P(CompositingTest, HitTestOpaqueness) {
  InitializeWithHTML(*WebView()->MainFrameImpl()->GetFrame(), R"HTML(
    <div id="transparent1" style="pointer-events: none; will-change: transform;
                                  width: 100px; height: 50px">
    </div>
    <div id="transparent2" style="pointer-events: none; will-change: transform;
                                  width: 100px; height: 50px; background: red">
    </div>

    <!-- Transparent parent with a small opaque child. -->
    <div id="mixed1" style="pointer-events: none; will-change: transform;
                            width: 200px; height: 50px">
      Transparent parent
      <div style="pointer-events: auto">Opaque child</div>
    </div>
    <!-- Layer with mixed opaque areas and transparent gaps. -->
    <div id="mixed2" style="will-change: transform; width: 0">
      <div style="margin: 10px; width: 200px; height: 50px">Opaque child1</div>
      <div style="margin: 10px; width: 200px; height: 50px">Opaque child2</div>
    </div>
    <div id="mixed3" style="will-change: transform; border-radius: 10px;
                            width: 50px; height: 50px">
    </div>

    <div id="opaque1" style="will-change: transform; width: 50px; height: 50px">
       Opaque
    </div>
    <!-- Two adjacent opaque children fills the layer, making the layer
         opaque. -->
    <div id="opaque2" style="will-change: transform; width: 0">
      <div style="width: 100px; height: 50px">Opaque child1</div>
      <div style="width: 100px; height: 50px">Opaque child2</div>
    </div>
    <!-- Child pointer-events:none doesn't affect opaqueness of parent. -->
    <div id="opaque3"
         style="will-change: transform; width: 100px; height: 100px">
      <div style="width: 50px; height: 50px; pointer-events: none"></div>
    </div>
    <!-- An opaque child fills the transparent parent, making the layer
         opaque. -->
    <div id="opaque4" style="will-change: transform; pointer-events: none">
      <div style="height: 50px; pointer-events: auto"></div>
    </div>
    <!-- An opaque child fills the mixed layer, making the layer opaque. -->
    <div id="opaque5" style="will-change: transform; border-radius: 10px;
                             width: 50px; height; 50px">
      <div style="height: 50px"></div>
    </div>
    <!-- This is opaque because the svg element (opaque to hit test) fully
         contains the circle (mixed opaqueness to hit test). -->
    <svg id="opaque6" style="will-change: transform">
      <circle cx="20" cy="20" r="20"/>
    </svg>
  )HTML");

  const auto hit_test_transparent =
      RuntimeEnabledFeatures::HitTestOpaquenessEnabled()
          ? cc::HitTestOpaqueness::kTransparent
          : cc::HitTestOpaqueness::kMixed;
  EXPECT_EQ(hit_test_transparent,
            CcLayersByDOMElementId(RootCcLayer(), "transparent1")[0]
                ->hit_test_opaqueness());
  EXPECT_EQ(hit_test_transparent,
            CcLayersByDOMElementId(RootCcLayer(), "transparent2")[0]
                ->hit_test_opaqueness());
  EXPECT_EQ(cc::HitTestOpaqueness::kMixed,
            CcLayersByDOMElementId(RootCcLayer(), "mixed1")[0]
                ->hit_test_opaqueness());
  EXPECT_EQ(cc::HitTestOpaqueness::kMixed,
            CcLayersByDOMElementId(RootCcLayer(), "mixed2")[0]
                ->hit_test_opaqueness());
  EXPECT_EQ(cc::HitTestOpaqueness::kMixed,
            CcLayersByDOMElementId(RootCcLayer(), "mixed3")[0]
                ->hit_test_opaqueness());
  const auto hit_test_opaque =
      RuntimeEnabledFeatures::HitTestOpaquenessEnabled()
          ? cc::HitTestOpaqueness::kOpaque
          : cc::HitTestOpaqueness::kMixed;
  EXPECT_EQ(hit_test_opaque, CcLayersByDOMElementId(RootCcLayer(), "opaque1")[0]
                                 ->hit_test_opaqueness());
  EXPECT_EQ(hit_test_opaque, CcLayersByDOMElementId(RootCcLayer(), "opaque2")[0]
                                 ->hit_test_opaqueness());
  EXPECT_EQ(hit_test_opaque, CcLayersByDOMElementId(RootCcLayer(), "opaque3")[0]
                                 ->hit_test_opaqueness());
  EXPECT_EQ(hit_test_opaque, CcLayersByDOMElementId(RootCcLayer(), "opaque4")[0]
                                 ->hit_test_opaqueness());
  EXPECT_EQ(hit_test_opaque, CcLayersByDOMElementId(RootCcLayer(), "opaque5")[0]
                                 ->hit_test_opaqueness());
  EXPECT_EQ(hit_test_opaque, CcLayersByDOMElementId(RootCcLayer(), "opaque6")[0]
                                 ->hit_test_opaqueness());
}

TEST_P(CompositingTest, HitTestOpaquenessOfSolidColorLayer) {
  InitializeWithHTML(*WebView()->MainFrameImpl()->GetFrame(), R"HTML(
    <div id="target" style="will-change: transform; width: 100px; height: 100px;
                            background: green">
    </div>
  )HTML");

  auto* layer = CcLayersByDOMElementId(RootCcLayer(), "target")[0];
  EXPECT_TRUE(layer->IsSolidColorLayerForTesting());
  if (RuntimeEnabledFeatures::HitTestOpaquenessEnabled()) {
    EXPECT_EQ(cc::HitTestOpaqueness::kOpaque, layer->hit_test_opaqueness());
  } else {
    EXPECT_EQ(cc::HitTestOpaqueness::kMixed, layer->hit_test_opaqueness());
  }
}

TEST_P(CompositingTest, HitTestOpaquenessOfEmptyInline) {
  InitializeWithHTML(*WebView()->MainFrameImpl()->GetFrame(), R"HTML(
    <style>
      html, body { margin: 0; }
      #inline {
        pointer-events: none;
      }
      #scrollable {
        width: 150px;
        height: 150px;
        overflow-y: scroll;
      }
      #scrollable::-webkit-scrollbar {
        display: none;
      }
      #content {
        height: 1000px;
        width: 150px;
        background: linear-gradient(blue, yellow);
        pointer-events: auto;
      }
    </style>
    <span id="inline"><div id="scrollable"><div id="content"></div></div></span>
  )HTML");

  // We should have a layer for the scrolling contents.
  auto* scrolling_contents =
      CcLayersByDOMElementId(RootCcLayer(), "scrollable").back();
  EXPECT_EQ(gfx::Size(150, 1000), scrolling_contents->bounds());

  // If there is a following layer for inline contents, it should be non-opaque.
  auto html_layers = CcLayersByName(RootCcLayer(), "LayoutBlockFlow HTML");
  auto* html = html_layers.empty() ? nullptr : html_layers.back();
  if (html) {
    EXPECT_GT(html->id(), scrolling_contents->id());
    EXPECT_EQ(gfx::Size(200, 150), html->bounds());
    EXPECT_NE(cc::HitTestOpaqueness::kOpaque, html->hit_test_opaqueness());
  }
}

TEST_P(CompositingTest, HitTestOpaquenessOnChangeOfUsedPointerEvents) {
  InitializeWithHTML(*WebView()->MainFrameImpl()->GetFrame(), R"HTML(
    <div id="parent">
      <div id="target" style="will-change: transform; width: 50px; height: 50px;
                              background: blue">
      </div>
    </div>
  )HTML");

  const auto hit_test_transparent =
      RuntimeEnabledFeatures::HitTestOpaquenessEnabled()
          ? cc::HitTestOpaqueness::kTransparent
          : cc::HitTestOpaqueness::kMixed;
  const auto hit_test_opaque =
      RuntimeEnabledFeatures::HitTestOpaquenessEnabled()
          ? cc::HitTestOpaqueness::kOpaque
          : cc::HitTestOpaqueness::kMixed;

  Element* parent = GetElementById("parent");
  Element* target = GetElementById("target");
  const LayoutBox* target_box = target->GetL
"""


```