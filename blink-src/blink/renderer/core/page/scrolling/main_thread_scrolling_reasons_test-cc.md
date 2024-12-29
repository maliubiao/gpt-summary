Response:
My thinking process to analyze the C++ test file and answer the request went through these stages:

1. **Understand the Goal:** The request asks for the functionality of the C++ test file, its relation to web technologies (JavaScript, HTML, CSS), examples of logical reasoning, common user/programming errors, and debugging hints.

2. **Identify the Core Purpose:** The filename `main_thread_scrolling_reasons_test.cc` and the presence of `#include "cc/input/main_thread_scrolling_reason.h"` strongly suggest this file is testing the conditions under which scrolling happens on the browser's main thread versus the compositor thread. This is a key performance optimization area in browsers.

3. **Scan for Key Concepts and Classes:** I looked for classes and functions within the code that point to the concepts being tested. Keywords like `MainThreadScrollingReason`, `ScrollNode`, `PaintLayerScrollableArea`, `cc::Layer`, and functions like `GetMainThreadRepaintReasons` are crucial. The presence of `SimTest`, `PaintTestConfigurations`, and the use of `frame_test_helpers` indicate this is a test fixture for rendering and compositing behavior.

4. **Analyze Test Cases:** I examined the individual `TEST_P` functions. Their names provide clear hints about the scenarios being tested:
    * `BackgroundAttachmentFixedShouldTriggerMainThreadScroll`: Tests the impact of `background-attachment: fixed`.
    * `ReportBackgroundAttachmentFixed`: Verifies that the correct metrics are reported for fixed background attachments.
    * `RecalculateMainThreadScrollingReasonsUponResize`: Checks if scrolling reasons are updated after a resize.
    * `FastScrollingForFixedPosition`, `FastScrollingForStickyPosition`, `FastScrollingByDefault`: Confirm that these positioning types generally allow compositor thread scrolling.
    * The `NonCompositedMainThreadScrollingReasonsTest` and its numerous tests (`TransparentTest`, `TransformTest`, etc.) clearly focus on scenarios where certain CSS properties force main thread scrolling when compositing is *not* explicitly triggered.

5. **Relate to Web Technologies (HTML, CSS, JavaScript):**
    * **HTML:** The tests use HTML elements (`<div>`, `<iframe>`) and attributes (`id`, `style`, `class`) to set up the test conditions.
    * **CSS:** The core of the testing revolves around CSS properties. `background-attachment: fixed`, `position: fixed`, `position: sticky`, `opacity`, `transform`, `background`, `clip`, `clip-path`, `box-shadow`, `border-radius`, and the concept of stacking contexts are all directly tested.
    * **JavaScript:** While this specific file doesn't heavily use JavaScript, the tests manipulate the DOM using Blink's C++ API (which is how JavaScript interacts with the rendering engine). The `removeAttribute` and `setAttribute` calls mimic JavaScript DOM manipulation.

6. **Identify Logical Reasoning:**  The tests follow a pattern of:
    * **Setup:** Load HTML, potentially with specific CSS.
    * **Action:**  Perform an action (like resizing or modifying attributes).
    * **Assertion:** Check the `MainThreadScrollingReason` using `EXPECT_MAIN_THREAD_SCROLLING_REASON` or `EXPECT_NO_MAIN_THREAD_SCROLLING_REASON`. The reasoning is that *if* a certain CSS property is present, *then* scrolling should (or shouldn't) happen on the main thread.

7. **Consider User/Programming Errors:** I thought about how developers might misuse these CSS features and trigger unexpected main thread scrolling, impacting performance. This leads to examples like unintentionally using `background-attachment: fixed` on large elements or overusing properties that inhibit compositor scrolling.

8. **Trace User Operations (Debugging Hints):** I imagined the steps a user might take in a browser that would lead to the execution paths tested in this file. This involves loading pages with specific CSS, scrolling, resizing the window, or interacting with elements that change their styling dynamically.

9. **Structure the Answer:** Finally, I organized my findings into the requested categories: Functionality, Relation to Web Technologies, Logical Reasoning, User/Programming Errors, and User Operation/Debugging. I used the information extracted from the code and my understanding of browser rendering to provide concrete examples.

Essentially, I treated the test file as documentation of the conditions that influence main thread scrolling in Blink. By dissecting the test cases and their assertions, I could infer the underlying logic and its connection to web standards.
这个文件 `main_thread_scrolling_reasons_test.cc` 是 Chromium Blink 渲染引擎的一部分，其主要功能是**测试在哪些情况下，页面的滚动操作会发生在主线程而不是合成器线程。**

**功能详解:**

* **测试滚动优化:**  Chromium 为了提升滚动性能，尽可能将滚动操作放在独立的合成器线程上执行，这样可以避免在滚动时阻塞主线程，从而保持用户界面的流畅性。这个测试文件的目的是验证各种 CSS 属性、HTML 结构和浏览器设置是否正确地触发了主线程滚动（当某些条件阻止合成器线程滚动时）。
* **覆盖各种场景:** 文件中包含了多个测试用例（以 `TEST_P` 开头），每个用例模拟了不同的网页结构和 CSS 样式，并断言在这些情况下是否应该发生主线程滚动。
* **使用 `cc::MainThreadScrollingReason` 枚举:**  测试使用 `cc::MainThreadScrollingReason` 这个枚举来表示触发主线程滚动的具体原因。这有助于精确地诊断问题。
* **集成测试框架:**  文件使用了 Google Test 框架 (`testing::Test`) 和 Blink 提供的测试工具 (`PaintTestConfigurations`, `SimTest`, `frame_test_helpers`) 来创建和管理测试环境，加载网页，并检查渲染结果。
* **度量指标测试:**  部分测试用例（如 `ReportBackgroundAttachmentFixed`)  还使用了 `base::HistogramTester` 来验证是否记录了正确的性能指标。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个测试文件与 HTML 和 CSS 的关系非常密切，因为它测试的是特定 HTML 结构和 CSS 样式如何影响浏览器的滚动行为。虽然没有直接涉及 JavaScript 代码的执行，但 JavaScript 动态修改 HTML 和 CSS 也会间接地影响这里测试的结果。

**HTML 举例:**

* **`<iframe>` 元素:**  测试用例 `BackgroundAttachmentFixedShouldTriggerMainThreadScroll` 中使用了 `<iframe>` 元素来模拟嵌套的文档结构，并测试在父窗口和子窗口中 `background-attachment: fixed` 的影响。
* **具有 `id` 属性的 `<div>` 元素:** 测试用例中经常使用带有 `id` 属性的 `<div>` 元素作为滚动容器或应用特定样式的目标，例如 `<div id="scrollable">` 或 `<div id="bg">`。

**CSS 举例:**

* **`background-attachment: fixed`:**  这是触发主线程滚动的经典场景。当元素具有 `background-attachment: fixed` 样式时，背景会相对于视口固定，这意味着每次滚动都需要重新绘制背景，通常发生在主线程。
   ```css
   body {
     background-image: url('image.png');
     background-attachment: fixed;
   }
   ```
* **`position: fixed` 和 `position: sticky`:** 测试用例 `FastScrollingForFixedPosition` 和 `FastScrollingForStickyPosition` 验证了通常情况下，`position: fixed` 和 `position: sticky` 的元素不会强制滚动发生在主线程，因为它们通常可以由合成器线程高效处理。
* **`opacity`，`transform`，`clip-path`，`box-shadow` 等:**  `NonCompositedMainThreadScrollingReasonsTest` 类下的多个测试用例测试了当元素应用了这些 CSS 属性，但没有被强制合成时，是否会触发主线程滚动。例如：
   ```css
   .transparent {
     opacity: 0.5;
   }
   .transform {
     transform: rotate(10deg);
   }
   ```
* **`background` 属性和不透明度:** 测试用例 `BackgroundNotOpaqueTest` 检查了当元素的背景不是完全不透明时，是否会影响滚动行为。

**JavaScript 举例 (间接关系):**

虽然测试文件中没有直接的 JavaScript 代码，但测试逻辑会模拟通过 JavaScript 动态修改元素属性的情况，例如：

```cpp
  element->setAttribute(html_names::kStyleAttr,
                        AtomicString("background-image: url('white-1x1.png'); "
                                     "background-attachment: fixed;"));
```

这模拟了 JavaScript 代码类似 `element.style.backgroundImage = "url('white-1x1.png')"; element.style.backgroundAttachment = "fixed";` 的操作。

**逻辑推理、假设输入与输出:**

测试用例通常会进行逻辑推理，基于特定的输入（HTML 结构、CSS 样式）来预测输出（是否发生主线程滚动以及具体原因）。

**假设输入 (以 `BackgroundAttachmentFixedShouldTriggerMainThreadScroll` 为例):**

1. **HTML:**  一个包含 `<iframe>` 元素的 HTML 页面，`<iframe>` 内部的文档包含一个带有 `background-attachment: fixed` 样式的元素。
   ```html
   <!-- iframe-background-attachment-fixed.html -->
   <!DOCTYPE html>
   <html>
   <head>
     <style>
       body { margin: 0; }
       #scrollable {
         width: 200px;
         height: 200px;
         overflow: auto;
       }
     </style>
   </head>
   <body>
     <div id="scrollable">
       <iframe id="iframe" src="iframe-background-attachment-fixed-inner.html"></iframe>
     </div>
   </body>
   </html>

   <!-- iframe-background-attachment-fixed-inner.html -->
   <!DOCTYPE html>
   <html>
   <head>
     <style>
       body { margin: 0; }
       .fixed-bg {
         width: 400px;
         height: 400px;
         background-image: url('white-1x1.png');
         background-attachment: fixed;
       }
     </style>
   </head>
   <body>
     <div id="content" class="fixed-bg"></div>
   </body>
   </html>
   ```
2. **执行操作:**  加载上述 HTML 页面并进行完整的合成更新。

**预期输出:**

* 对于 `<iframe>` 内部的滚动区域，`GetMainThreadRepaintReasons` 应该返回 `cc::MainThreadScrollingReason::kHasBackgroundAttachmentFixedObjects`，表明由于 `background-attachment: fixed`，滚动可能发生在主线程。
* 对于主文档的滚动区域，如果它本身没有触发主线程滚动的因素，则 `GetMainThreadRepaintReasons` 应该返回 `cc::MainThreadScrollingReason::kNotScrollingOnMain`。

**用户或编程常见的使用错误及举例说明:**

* **过度使用 `background-attachment: fixed`:**  开发者可能在不需要的情况下对很多元素应用 `background-attachment: fixed`，导致页面滚动性能下降，因为这会迫使浏览器在每次滚动时都重新绘制这些背景。
   ```css
   /* 错误示例：不必要地在多个元素上使用 fixed background */
   .section1, .section2, .footer {
     background-image: url('pattern.png');
     background-attachment: fixed;
   }
   ```
* **误解合成的条件:**  开发者可能认为只要使用了硬件加速相关的 CSS 属性（如 `transform`），滚动就一定发生在合成器线程。但实际上，即使使用了这些属性，如果还有其他因素（如非不透明的渲染、某些复杂的裁剪等），仍然可能导致主线程滚动。
* **动态修改可能触发主线程滚动的属性:**  JavaScript 代码可能在滚动过程中动态修改元素的 CSS 属性，例如改变 `opacity` 或 `transform`，这可能会意外地将滚动操作切换到主线程，导致性能抖动。

**用户操作如何一步步到达这里，作为调试线索:**

1. **用户访问包含特定 CSS 属性的网页:** 用户通过浏览器访问了一个包含可能触发主线程滚动的 CSS 属性（如 `background-attachment: fixed`）的网页。
2. **用户滚动页面:** 用户使用鼠标滚轮、触摸屏滑动或键盘操作滚动页面。
3. **浏览器渲染引擎进行滚动处理:**
   * 浏览器会检查滚动相关的元素是否满足合成器线程滚动的条件。
   * 如果存在像 `background-attachment: fixed` 这样的属性，或者其他需要主线程处理的情况，滚动操作会被分配到主线程。
4. **`main_thread_scrolling_reasons_test.cc` 的价值:**  在开发或调试浏览器渲染引擎时，开发者可能会修改与滚动相关的代码。这个测试文件可以用来验证这些修改是否引入了新的主线程滚动情况，或者是否正确地优化了滚动性能。如果一个修改导致本该在合成器线程滚动的场景变成了主线程滚动，相应的测试用例将会失败，提示开发者需要仔细检查代码。

**调试线索:**

* **性能分析工具:**  Chromium 开发者可以使用内置的性能分析工具（如 DevTools 的 Performance 面板）来观察滚动时的线程活动，查看是否有大量的“Paint”操作发生在主线程。
* **`chrome://flags`:**  某些实验性的渲染特性可能会影响滚动行为，开发者可以通过 `chrome://flags` 来调整这些设置，并观察其对测试结果的影响。
* **代码断点和日志:**  在 `main_thread_scrolling_reasons_test.cc` 中设置断点，或者在相关的渲染引擎代码中添加日志，可以帮助开发者更深入地理解滚动决策的过程。
* **阅读和理解测试用例:**  仔细阅读和理解 `main_thread_scrolling_reasons_test.cc` 中的测试用例，可以帮助开发者了解哪些 CSS 属性和场景已知会影响滚动线程。当遇到意外的主线程滚动时，可以尝试构建类似的测试用例来重现问题并进行调试。

总而言之，`main_thread_scrolling_reasons_test.cc` 是一个至关重要的测试文件，用于确保 Chromium 的滚动优化策略能够正确工作，并在各种网页场景下提供流畅的滚动体验。它通过测试各种 HTML 和 CSS 的组合，来验证滚动操作是否按预期发生在合成器线程，并在必要时准确地检测和报告主线程滚动的原因。

Prompt: 
```
这是目录为blink/renderer/core/page/scrolling/main_thread_scrolling_reasons_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/test/metrics/histogram_tester.h"
#include "cc/input/main_thread_scrolling_reason.h"
#include "cc/layers/picture_layer.h"
#include "cc/trees/property_tree.h"
#include "cc/trees/scroll_node.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/frame/web_frame_widget_impl.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/html/html_iframe_element.h"
#include "third_party/blink/renderer/core/layout/layout_embedded_content.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/graphics/compositing/paint_artifact_compositor.h"
#include "third_party/blink/renderer/platform/testing/find_cc_layer.h"
#include "third_party/blink/renderer/platform/testing/paint_test_configurations.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/url_loader_mock_factory.h"
#include "third_party/blink/renderer/platform/testing/url_test_helpers.h"

namespace blink {

#define EXPECT_MAIN_THREAD_SCROLLING_REASON(expected, actual)             \
  EXPECT_EQ(expected, actual)                                             \
      << " expected: " << cc::MainThreadScrollingReason::AsText(expected) \
      << " actual: " << cc::MainThreadScrollingReason::AsText(actual)

#define EXPECT_NO_MAIN_THREAD_SCROLLING_REASON(actual)                  \
  EXPECT_EQ(cc::MainThreadScrollingReason::kNotScrollingOnMain, actual) \
      << " actual: " << cc::MainThreadScrollingReason::AsText(actual)

class MainThreadScrollingReasonsTest : public PaintTestConfigurations,
                                       public testing::Test {
 public:
  MainThreadScrollingReasonsTest() : base_url_("http://www.test.com/") {
    helper_.Initialize();
    GetFrame()->GetSettings()->SetPreferCompositingToLCDTextForTesting(true);
    GetWebView()->MainFrameViewWidget()->Resize(gfx::Size(320, 240));
    GetWebView()->MainFrameViewWidget()->UpdateAllLifecyclePhases(
        DocumentUpdateReason::kTest);
  }

  ~MainThreadScrollingReasonsTest() override {
    url_test_helpers::UnregisterAllURLsAndClearMemoryCache();
  }

  void NavigateTo(const String& url) {
    frame_test_helpers::LoadFrame(GetWebView()->MainFrameImpl(), url.Utf8());
  }

  void LoadHTML(const String& html) {
    frame_test_helpers::LoadHTMLString(GetWebView()->MainFrameImpl(),
                                       html.Utf8(),
                                       url_test_helpers::ToKURL("about:blank"));
  }

  void ForceFullCompositingUpdate() {
    GetWebView()->MainFrameViewWidget()->UpdateAllLifecyclePhases(
        DocumentUpdateReason::kTest);
  }

  void RegisterMockedHttpURLLoad(const String& file_name) {
    // TODO(crbug.com/751425): We should use the mock functionality
    // via |helper_|.
    url_test_helpers::RegisterMockedURLLoadFromBase(
        WebString(base_url_), test::CoreTestDataPath(), WebString(file_name));
  }

  const cc::ScrollNode* GetScrollNode(const cc::Layer* layer) const {
    return layer->layer_tree_host()
        ->property_trees()
        ->scroll_tree()
        .FindNodeFromElementId(layer->element_id());
  }

  const cc::ScrollNode* GetScrollNode(
      const PaintLayerScrollableArea& scrollable_area) const {
    return GetFrame()
        ->View()
        ->RootCcLayer()
        ->layer_tree_host()
        ->property_trees()
        ->scroll_tree()
        .FindNodeFromElementId(scrollable_area.GetScrollElementId());
  }

  uint32_t GetMainThreadRepaintReasons(const cc::Layer* layer) const {
    return GetScrollNode(layer)->main_thread_repaint_reasons;
  }

  uint32_t GetMainThreadRepaintReasons(
      const ScrollPaintPropertyNode& scroll) const {
    return GetFrame()
        ->View()
        ->GetPaintArtifactCompositor()
        ->GetMainThreadRepaintReasons(scroll);
  }

  uint32_t GetMainThreadRepaintReasons(
      const PaintLayerScrollableArea& scrollable_area) const {
    return GetMainThreadRepaintReasons(*scrollable_area.GetLayoutBox()
                                            ->FirstFragment()
                                            .PaintProperties()
                                            ->Scroll());
  }

  uint32_t GetViewMainThreadRepaintReasons() const {
    return GetMainThreadRepaintReasons(*GetFrame()->View()->LayoutViewport());
  }

  WebViewImpl* GetWebView() const { return helper_.GetWebView(); }
  LocalFrame* GetFrame() const { return helper_.LocalMainFrame()->GetFrame(); }
  PaintLayerScrollableArea* GetScrollableArea(const Element& element) const {
    return To<LayoutBoxModelObject>(element.GetLayoutObject())
        ->GetScrollableArea();
  }

 protected:
  test::TaskEnvironment task_environment_;
  String base_url_;
  frame_test_helpers::WebViewHelper helper_;
};

INSTANTIATE_PAINT_TEST_SUITE_P(MainThreadScrollingReasonsTest);

// More cases are tested in LocalFrameViewTest
// .RequiresMainThreadScrollingForBackgroundFixedAttachment.
TEST_P(MainThreadScrollingReasonsTest,
       BackgroundAttachmentFixedShouldTriggerMainThreadScroll) {
  RegisterMockedHttpURLLoad("iframe-background-attachment-fixed.html");
  RegisterMockedHttpURLLoad("iframe-background-attachment-fixed-inner.html");
  RegisterMockedHttpURLLoad("white-1x1.png");
  NavigateTo(base_url_ + "iframe-background-attachment-fixed.html");
  ForceFullCompositingUpdate();

  auto* root_layer = GetFrame()->View()->RootCcLayer();
  auto* outer_layout_view = GetFrame()->View()->GetLayoutView();
  Element* iframe =
      GetFrame()->GetDocument()->getElementById(AtomicString("iframe"));
  ASSERT_TRUE(iframe);

  LocalFrameView* inner_frame_view = To<LocalFrameView>(
      To<LayoutEmbeddedContent>(iframe->GetLayoutObject())->ChildFrameView());
  ASSERT_TRUE(inner_frame_view);
  auto* inner_layout_view = inner_frame_view->GetLayoutView();
  ASSERT_TRUE(inner_layout_view);

  auto* inner_scroll_node =
      inner_layout_view->FirstFragment().PaintProperties()->Scroll();
  ASSERT_TRUE(inner_scroll_node);
  EXPECT_MAIN_THREAD_SCROLLING_REASON(
      cc::MainThreadScrollingReason::kHasBackgroundAttachmentFixedObjects,
      GetMainThreadRepaintReasons(*inner_scroll_node));
  const cc::Layer* inner_scroll_layer = CcLayerByCcElementId(
      root_layer, inner_scroll_node->GetCompositorElementId());
  ASSERT_TRUE(inner_scroll_layer);
  EXPECT_MAIN_THREAD_SCROLLING_REASON(
      cc::MainThreadScrollingReason::kHasBackgroundAttachmentFixedObjects,
      GetMainThreadRepaintReasons(inner_scroll_layer));

  // Main thread scrolling of the inner layer doesn't affect the outer layer.
  auto* outer_scroll_node = GetFrame()
                                ->View()
                                ->GetLayoutView()
                                ->FirstFragment()
                                .PaintProperties()
                                ->Scroll();
  ASSERT_TRUE(outer_scroll_node);
  EXPECT_NO_MAIN_THREAD_SCROLLING_REASON(
      GetMainThreadRepaintReasons(*outer_scroll_node));
  const cc::Layer* outer_scroll_layer = CcLayerByCcElementId(
      root_layer, outer_scroll_node->GetCompositorElementId());
  ASSERT_TRUE(outer_scroll_layer);
  EXPECT_NO_MAIN_THREAD_SCROLLING_REASON(
      GetMainThreadRepaintReasons(outer_scroll_layer));

  // Remove fixed background-attachment should make the iframe scroll on cc.
  auto* content =
      inner_layout_view->GetDocument().getElementById(AtomicString("content"));
  ASSERT_TRUE(content);
  content->removeAttribute(html_names::kClassAttr);

  ForceFullCompositingUpdate();

  ASSERT_EQ(inner_scroll_node,
            inner_layout_view->FirstFragment().PaintProperties()->Scroll());
  EXPECT_NO_MAIN_THREAD_SCROLLING_REASON(
      GetMainThreadRepaintReasons(*inner_scroll_node));
  ASSERT_EQ(inner_scroll_layer,
            CcLayerByCcElementId(root_layer,
                                 inner_scroll_node->GetCompositorElementId()));
  EXPECT_NO_MAIN_THREAD_SCROLLING_REASON(
      GetMainThreadRepaintReasons(inner_scroll_layer));

  ASSERT_EQ(outer_scroll_node,
            outer_layout_view->FirstFragment().PaintProperties()->Scroll());
  EXPECT_NO_MAIN_THREAD_SCROLLING_REASON(
      GetMainThreadRepaintReasons(*outer_scroll_node));
  ASSERT_EQ(outer_scroll_layer,
            CcLayerByCcElementId(root_layer,
                                 outer_scroll_node->GetCompositorElementId()));
  EXPECT_NO_MAIN_THREAD_SCROLLING_REASON(
      GetMainThreadRepaintReasons(outer_scroll_layer));

  // Force main frame to scroll on main thread. All its descendants
  // should scroll on main thread as well.
  Element* element =
      GetFrame()->GetDocument()->getElementById(AtomicString("scrollable"));
  element->setAttribute(
      html_names::kStyleAttr,
      AtomicString(
          "background-image: url('white-1x1.png'), url('white-1x1.png');"
          "                  background-attachment: fixed, local;"));

  ForceFullCompositingUpdate();

  // Main thread scrolling of the outer layer affects the inner layer.
  ASSERT_EQ(inner_scroll_node,
            inner_layout_view->FirstFragment().PaintProperties()->Scroll());
  EXPECT_MAIN_THREAD_SCROLLING_REASON(
      cc::MainThreadScrollingReason::kHasBackgroundAttachmentFixedObjects,
      GetMainThreadRepaintReasons(*inner_scroll_node));
  ASSERT_EQ(inner_scroll_layer,
            CcLayerByCcElementId(root_layer,
                                 inner_scroll_node->GetCompositorElementId()));
  EXPECT_MAIN_THREAD_SCROLLING_REASON(
      cc::MainThreadScrollingReason::kHasBackgroundAttachmentFixedObjects,
      GetMainThreadRepaintReasons(inner_scroll_layer));

  ASSERT_EQ(outer_scroll_node,
            outer_layout_view->FirstFragment().PaintProperties()->Scroll());
  EXPECT_MAIN_THREAD_SCROLLING_REASON(
      cc::MainThreadScrollingReason::kHasBackgroundAttachmentFixedObjects,
      GetMainThreadRepaintReasons(*outer_scroll_node));
  ASSERT_EQ(outer_scroll_layer,
            CcLayerByCcElementId(root_layer,
                                 outer_scroll_node->GetCompositorElementId()));
  EXPECT_MAIN_THREAD_SCROLLING_REASON(
      cc::MainThreadScrollingReason::kHasBackgroundAttachmentFixedObjects,
      GetMainThreadRepaintReasons(outer_scroll_layer));
}

TEST_P(MainThreadScrollingReasonsTest, ReportBackgroundAttachmentFixed) {
  base::HistogramTester histogram_tester;
  std::string html = R"HTML(
    <style>
      body { width: 900px; height: 900px; }
      #bg {
        background: url('white-1x1.png') fixed, url('white-1x1.png') local;
      }
    </style>
    <div id=bg>x</div>
  )HTML";

  WebLocalFrameImpl* frame = helper_.LocalMainFrame();
  frame_test_helpers::LoadHTMLString(frame, html,
                                     url_test_helpers::ToKURL("about:blank"));

  helper_.GetLayerTreeHost()->CompositeForTest(base::TimeTicks::Now(), false,
                                               base::OnceClosure());

  auto CreateEvent = [](WebInputEvent::Type type) {
    return WebGestureEvent(type, WebInputEvent::kNoModifiers,
                           base::TimeTicks::Now(),
                           WebGestureDevice::kTouchscreen);
  };

  WebGestureEvent scroll_begin =
      CreateEvent(WebInputEvent::Type::kGestureScrollBegin);
  WebGestureEvent scroll_update =
      CreateEvent(WebInputEvent::Type::kGestureScrollUpdate);
  WebGestureEvent scroll_end =
      CreateEvent(WebInputEvent::Type::kGestureScrollEnd);

  scroll_begin.SetPositionInWidget(gfx::PointF(100, 100));
  scroll_update.SetPositionInWidget(gfx::PointF(100, 100));
  scroll_end.SetPositionInWidget(gfx::PointF(100, 100));

  scroll_update.data.scroll_update.delta_y = -100;

  auto* widget = helper_.GetMainFrameWidget();
  widget->DispatchThroughCcInputHandler(scroll_begin);
  widget->DispatchThroughCcInputHandler(scroll_update);
  widget->DispatchThroughCcInputHandler(scroll_end);

  helper_.GetLayerTreeHost()->CompositeForTest(base::TimeTicks::Now(), false,
                                               base::OnceClosure());

  uint32_t expected_reason =
      cc::MainThreadScrollingReason::kHasBackgroundAttachmentFixedObjects;
  EXPECT_THAT(
      histogram_tester.GetAllSamples(
          "Renderer4.MainThreadGestureScrollReason2"),
      testing::ElementsAre(
          base::Bucket(
              base::HistogramBase::Sample(
                  cc::MainThreadScrollingReason::kScrollingOnMainForAnyReason),
              1),
          base::Bucket(base::HistogramBase::Sample(
                           cc::MainThreadScrollingReason::BucketIndexForTesting(
                               expected_reason)),
                       1)));
}

// Upon resizing the content size, the main thread scrolling reason
// kHasBackgroundAttachmentFixedObjects should be updated on all frames
TEST_P(MainThreadScrollingReasonsTest,
       RecalculateMainThreadScrollingReasonsUponResize) {
  GetFrame()->GetSettings()->SetPreferCompositingToLCDTextForTesting(false);
  RegisterMockedHttpURLLoad("has-non-layer-viewport-constrained-objects.html");
  RegisterMockedHttpURLLoad("white-1x1.png");
  NavigateTo(base_url_ + "has-non-layer-viewport-constrained-objects.html");
  ForceFullCompositingUpdate();

  // When the main document is not scrollable, there should be no reasons.
  EXPECT_FALSE(GetViewMainThreadRepaintReasons());

  // When the div forces the document to be scrollable, it should scroll on main
  // thread.
  Element* element =
      GetFrame()->GetDocument()->getElementById(AtomicString("scrollable"));
  element->setAttribute(html_names::kStyleAttr,
                        AtomicString("background-image: url('white-1x1.png'); "
                                     "background-attachment: fixed;"));
  ForceFullCompositingUpdate();

  EXPECT_MAIN_THREAD_SCROLLING_REASON(
      cc::MainThreadScrollingReason::kHasBackgroundAttachmentFixedObjects,
      GetViewMainThreadRepaintReasons());

  // The main thread scrolling reason should be reset upon the following change.
  element->setAttribute(html_names::kStyleAttr, g_empty_atom);
  ForceFullCompositingUpdate();

  EXPECT_FALSE(GetViewMainThreadRepaintReasons());
}

TEST_P(MainThreadScrollingReasonsTest, FastScrollingForFixedPosition) {
  RegisterMockedHttpURLLoad("fixed-position.html");
  NavigateTo(base_url_ + "fixed-position.html");
  ForceFullCompositingUpdate();

  // Fixed position should not fall back to main thread scrolling.
  EXPECT_FALSE(GetViewMainThreadRepaintReasons());
}

TEST_P(MainThreadScrollingReasonsTest, FastScrollingForStickyPosition) {
  RegisterMockedHttpURLLoad("sticky-position.html");
  NavigateTo(base_url_ + "sticky-position.html");
  ForceFullCompositingUpdate();

  // Sticky position should not fall back to main thread scrolling.
  EXPECT_FALSE(GetViewMainThreadRepaintReasons());
}

TEST_P(MainThreadScrollingReasonsTest, FastScrollingByDefault) {
  GetWebView()->MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  LoadHTML("<div id='spacer' style='height: 1000px'></div>");
  ForceFullCompositingUpdate();

  // Fast scrolling should be enabled by default.
  EXPECT_FALSE(GetViewMainThreadRepaintReasons());

  const cc::Layer* visual_viewport_scroll_layer =
      GetFrame()->GetPage()->GetVisualViewport().LayerForScrolling();
  EXPECT_FALSE(GetMainThreadRepaintReasons(visual_viewport_scroll_layer));
}

class NonCompositedMainThreadScrollingReasonsTest
    : public MainThreadScrollingReasonsTest {
  static const uint32_t kLCDTextRelatedReasons =
      cc::MainThreadScrollingReason::kNotOpaqueForTextAndLCDText;

 protected:
  NonCompositedMainThreadScrollingReasonsTest() {
    RegisterMockedHttpURLLoad("two_scrollable_area.html");
    NavigateTo(base_url_ + "two_scrollable_area.html");
  }

  void TestNonCompositedReasons(const char* style_class,
                                const uint32_t reason) {
    AtomicString style_class_string(style_class);
    GetFrame()->GetSettings()->SetPreferCompositingToLCDTextForTesting(false);
    Document* document = GetFrame()->GetDocument();
    Element* container = document->getElementById(AtomicString("scroller1"));
    ForceFullCompositingUpdate();

    PaintLayerScrollableArea* scrollable_area = GetScrollableArea(*container);
    ASSERT_TRUE(scrollable_area);
    EXPECT_NO_MAIN_THREAD_SCROLLING_REASON(
        GetMainThreadRepaintReasons(*scrollable_area));

    container->classList().Add(style_class_string);
    ForceFullCompositingUpdate();

    ASSERT_TRUE(scrollable_area);
    EXPECT_MAIN_THREAD_SCROLLING_REASON(
        reason, GetMainThreadRepaintReasons(*scrollable_area));

    Element* container2 = document->getElementById(AtomicString("scroller2"));
    PaintLayerScrollableArea* scrollable_area2 = GetScrollableArea(*container2);
    ASSERT_TRUE(scrollable_area2);
    // Different scrollable area should remain unaffected.
    EXPECT_NO_MAIN_THREAD_SCROLLING_REASON(
        GetMainThreadRepaintReasons(*scrollable_area2));

    EXPECT_NO_MAIN_THREAD_SCROLLING_REASON(GetViewMainThreadRepaintReasons());

    // Remove class from the scroller 1 would lead to scroll on impl.
    container->classList().Remove(style_class_string);
    ForceFullCompositingUpdate();

    EXPECT_NO_MAIN_THREAD_SCROLLING_REASON(
        GetMainThreadRepaintReasons(*scrollable_area));
    EXPECT_NO_MAIN_THREAD_SCROLLING_REASON(GetViewMainThreadRepaintReasons());

    // Add target attribute would again lead to scroll on main thread
    container->classList().Add(style_class_string);
    ForceFullCompositingUpdate();

    EXPECT_MAIN_THREAD_SCROLLING_REASON(
        reason, GetMainThreadRepaintReasons(*scrollable_area));
    EXPECT_NO_MAIN_THREAD_SCROLLING_REASON(GetViewMainThreadRepaintReasons());

    if ((reason & kLCDTextRelatedReasons) &&
        !(reason & ~kLCDTextRelatedReasons)) {
      GetFrame()->GetSettings()->SetPreferCompositingToLCDTextForTesting(true);
      ForceFullCompositingUpdate();
      EXPECT_NO_MAIN_THREAD_SCROLLING_REASON(
          GetMainThreadRepaintReasons(*scrollable_area));
      EXPECT_NO_MAIN_THREAD_SCROLLING_REASON(GetViewMainThreadRepaintReasons());
    }
  }
};

INSTANTIATE_PAINT_TEST_SUITE_P(NonCompositedMainThreadScrollingReasonsTest);

TEST_P(NonCompositedMainThreadScrollingReasonsTest, TransparentTest) {
  TestNonCompositedReasons("transparent",
                           cc::MainThreadScrollingReason::kNotScrollingOnMain);
}

TEST_P(NonCompositedMainThreadScrollingReasonsTest, TransformTest) {
  TestNonCompositedReasons("transform",
                           cc::MainThreadScrollingReason::kNotScrollingOnMain);
}

TEST_P(NonCompositedMainThreadScrollingReasonsTest, BackgroundNotOpaqueTest) {
  TestNonCompositedReasons(
      "background-not-opaque",
      RuntimeEnabledFeatures::RasterInducingScrollEnabled()
          ? cc::MainThreadScrollingReason::kNotScrollingOnMain
          : cc::MainThreadScrollingReason::kNotOpaqueForTextAndLCDText);
}

TEST_P(NonCompositedMainThreadScrollingReasonsTest,
       CantPaintScrollingBackgroundTest) {
  TestNonCompositedReasons(
      "cant-paint-scrolling-background",
      RuntimeEnabledFeatures::RasterInducingScrollEnabled()
          ? cc::MainThreadScrollingReason::kBackgroundNeedsRepaintOnScroll
          : cc::MainThreadScrollingReason::kBackgroundNeedsRepaintOnScroll |
                cc::MainThreadScrollingReason::kNotOpaqueForTextAndLCDText);
}

TEST_P(NonCompositedMainThreadScrollingReasonsTest,
       BackgroundNeedsRepaintOnScroll) {
  TestNonCompositedReasons(
      "needs-repaint-on-scroll",
      cc::MainThreadScrollingReason::kBackgroundNeedsRepaintOnScroll);
}

TEST_P(NonCompositedMainThreadScrollingReasonsTest, ClipTest) {
  TestNonCompositedReasons("clip",
                           cc::MainThreadScrollingReason::kNotScrollingOnMain);
}

TEST_P(NonCompositedMainThreadScrollingReasonsTest, ClipPathTest) {
  TestNonCompositedReasons("clip-path",
                           cc::MainThreadScrollingReason::kNotScrollingOnMain);
}

TEST_P(NonCompositedMainThreadScrollingReasonsTest, BoxShadowTest) {
  TestNonCompositedReasons("box-shadow",
                           cc::MainThreadScrollingReason::kNotScrollingOnMain);
}

TEST_P(NonCompositedMainThreadScrollingReasonsTest, InsetBoxShadowTest) {
  TestNonCompositedReasons(
      "inset-box-shadow",
      RuntimeEnabledFeatures::RasterInducingScrollEnabled()
          ? cc::MainThreadScrollingReason::kNotScrollingOnMain
          : cc::MainThreadScrollingReason::kNotOpaqueForTextAndLCDText);
}

TEST_P(NonCompositedMainThreadScrollingReasonsTest, StackingContextTest) {
  TestNonCompositedReasons("non-stacking-context",
                           cc::MainThreadScrollingReason::kNotScrollingOnMain);
}

TEST_P(NonCompositedMainThreadScrollingReasonsTest, BorderRadiusTest) {
  TestNonCompositedReasons("border-radius",
                           cc::MainThreadScrollingReason::kNotScrollingOnMain);
}

TEST_P(NonCompositedMainThreadScrollingReasonsTest,
       ForcedComositingWithLCDRelatedReasons) {
  // With "will-change:transform" we composite elements with
  // LCDTextRelatedReasons only. For elements with other NonCompositedReasons,
  // we don't composite them.
  GetFrame()->GetSettings()->SetPreferCompositingToLCDTextForTesting(false);
  Document* document = GetFrame()->GetDocument();
  Element* container = document->getElementById(AtomicString("scroller1"));
  ASSERT_TRUE(container);
  container->setAttribute(html_names::kClassAttr,
                          AtomicString("scroller composited transparent"));
  ForceFullCompositingUpdate();

  PaintLayerScrollableArea* scrollable_area = GetScrollableArea(*container);
  ASSERT_TRUE(scrollable_area);
  EXPECT_NO_MAIN_THREAD_SCROLLING_REASON(
      GetMainThreadRepaintReasons(*scrollable_area));

  Element* container2 = document->getElementById(AtomicString("scroller2"));
  ASSERT_TRUE(container2);
  container2->setAttribute(html_names::kClassAttr,
                           AtomicString("scroller composited border-radius"));
  ForceFullCompositingUpdate();
  PaintLayerScrollableArea* scrollable_area2 = GetScrollableArea(*container2);
  ASSERT_TRUE(scrollable_area2);
  EXPECT_TRUE(GetScrollNode(*scrollable_area2)->is_composited);
}

}  // namespace blink

"""

```