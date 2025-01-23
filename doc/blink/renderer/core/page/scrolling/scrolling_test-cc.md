Response:
The user wants to understand the functionality of the given C++ source code file `scrolling_test.cc`. I need to analyze the included headers and the structure of the `ScrollingTest` class to determine the file's purpose. Specifically, I need to identify if it relates to Javascript, HTML, or CSS and provide examples. I also need to consider potential user errors and how they might lead to debugging this file. Finally, I need to summarize the functionalities described in this first part of the file.

**Analysis of the code:**

*   **Includes:** The included headers reveal the file is part of Blink's rendering engine and focuses on testing the scrolling functionality. Keywords like "scrolling," "animation," "compositor," "layer," and "event" are significant. It also uses the `testing/gtest` framework, indicating it's a unit test file.
*   **`ScrollingTest` Class:** This class inherits from `testing::Test` and `PaintTestConfigurations`, confirming its role as a test fixture. The setup involves initializing Blink, resizing the viewport, and updating lifecycle phases. Methods like `NavigateToHttp`, `LoadHTML`, and `ForceFullCompositingUpdate` suggest it's testing how scrolling interacts with different page states and content. The presence of methods like `ScrollableAreaByDOMElementId` and `ScrollNodeByDOMElementId` points to tests involving specific DOM elements and their scrolling behavior.
*   **Macros:**  `ASSERT_COMPOSITED` and `ASSERT_NOT_COMPOSITED` are used to verify whether a scroll node is composited or not, which is a crucial aspect of Blink's scrolling optimization.
*   **Test Cases:** The test cases (starting with `TEST_P`) cover various scrolling scenarios, including default fast scrolling, fractional scrolling, fixed and sticky positioning, event handling (pointer, touch, wheel, scroll), touch action, and how these interact with different DOM structures and CSS properties.

**Connections to Javascript, HTML, and CSS:**

*   **Javascript:** Event listeners (`addEventListener`) are explicitly mentioned and tested (e.g., `touchEventHandler`, `wheelEventHandler`). The test checks how Javascript event handlers impact scrolling behavior and whether they cause main-thread blocking.
*   **HTML:**  The tests load HTML snippets (`LoadHTML`) and navigate to HTML files (`SetupHttpTestURL`). They target specific HTML elements by their IDs (`getElementById`). The structure of the HTML influences scrolling behavior, and the tests verify this.
*   **CSS:** CSS properties like `position: fixed`, `position: sticky`, `touch-action`, `overflow`, and `box-shadow` are used in the test cases. The tests verify how these CSS properties affect scrolling and compositing.

**User/Programming Errors:** The tests implicitly check for errors by validating expected behavior under different conditions. Incorrectly setting CSS properties or adding blocking event listeners can lead to non-composited scrolling, which these tests aim to detect.

**User Operations:**  The tests simulate user actions that trigger scrolling, like touch events and mouse wheel events, even though the tests themselves don't involve direct user interaction. Debugging this file might be necessary when users report issues with smooth scrolling or unexpected touch behavior.

**Part 1 Summary:** This part of `scrolling_test.cc` sets up the testing environment and defines various tests to verify the core scrolling functionalities in the Blink rendering engine. It focuses on ensuring that fast (composited) scrolling is enabled by default and that specific HTML structures and CSS properties (like fixed and sticky positioning, touch-action) do not inadvertently disable it. It also tests the impact of Javascript event handlers on scrolling performance and touch interaction.
这是文件 `blink/renderer/core/page/scrolling/scrolling_test.cc` 的第一部分，它是一个 Chromium Blink 引擎的源代码文件，专门用于**测试 Blink 渲染引擎中的滚动 (scrolling) 功能**。

**具体功能归纳：**

1. **建立测试环境:**  它使用 Google Test (gtest) 框架来定义和运行测试用例。`ScrollingTest` 类继承自 `testing::Test`，提供了一个用于测试滚动功能的基类。它初始化了 Blink 引擎的环境，包括设置窗口大小和更新渲染生命周期。
2. **提供加载内容的方法:** 它包含用于加载不同类型的网页内容的方法，例如：
    *   `NavigateToHttp`/`NavigateToHttps`:  加载指定 HTTP/HTTPS URL 的网页。
    *   `LoadHTML`:  加载给定的 HTML 字符串。
    *   `SetupHttpTestURL`/`SetupHttpsTestURL`: 结合了加载 URL 和更新渲染的功能，方便测试。
3. **提供访问 Blink 内部组件的方法:** 它提供了一些辅助方法来访问 Blink 内部的组件，以便进行断言和验证，例如：
    *   `GetWebView`/`GetFrame`: 获取 `WebViewImpl` 和 `LocalFrame` 对象。
    *   `ScrollableAreaByDOMElementId`/`ScrollNodeByDOMElementId`:  根据 DOM 元素的 ID 获取其对应的可滚动区域和滚动节点。
    *   `CurrentScrollOffset`: 获取当前滚动偏移量。
    *   `RootCcLayer`: 获取根合成层。
    *   `LayerTreeHost`: 获取图层树宿主。
4. **测试默认的快速滚动 (Composited Scrolling):**  测试用例 `fastScrollingByDefault` 验证了在默认情况下，页面的滚动是否是快速滚动，即是否使用了合成器进行滚动，从而避免在主线程上进行昂贵的重绘操作。
5. **测试分数滚动偏移 (Fractional Scroll Offsets):** 测试用例 `fastFractionalScrollingDiv` 检查了当滚动偏移量是分数时，是否能正确地传递到合成器。
6. **测试固定定位 (Fixed Position) 元素的滚动:** 测试用例 `fastScrollingForFixedPosition` 验证了固定定位的元素不会导致回退到主线程滚动。
7. **测试粘性定位 (Sticky Position) 元素的滚动:** 测试用例 `fastScrollingForStickyPosition` 验证了粘性定位的元素也能利用快速滚动，并检查了粘性约束的属性。
8. **测试事件处理器的影响:**  一系列测试用例 (`elementPointerEventHandler`, `touchEventHandler` 等) 检查了不同类型的事件监听器（如 `pointerdown`, `touchstart`, `wheel`）及其选项（如 `passive: false`, `blocking: false`) 如何影响滚动的行为以及是否会阻止合成器滚动。例如，它会检查是否生成了阻止触摸操作的区域 (touch action regions)。
9. **测试 `touch-action` CSS 属性:**  多个测试用例 (`touchAction`, `touchActionRegions` 等)  验证了 `touch-action` CSS 属性如何影响元素的触摸行为，以及如何在不同的嵌套场景下生效。它会检查合成层上的触摸操作区域是否符合预期。
10. **测试滚动事件处理器:** 测试用例 `scrollEventHandler` 检查了是否存在滚动事件处理器。

**与 Javascript, HTML, CSS 的关系举例说明：**

*   **Javascript:**
    *   **举例:** `elementBlockingTouchEventHandler` 测试用例创建了一个带有 `touchstart` 事件监听器并且 `passive: false` 的 `div` 元素。这会阻止浏览器的默认触摸滚动行为，需要由 Javascript 代码来处理触摸事件。
        ```html
        <div id="blocking" style="width: 100px; height: 100px;"></div>
        <script>
          blocking.addEventListener('touchstart', function(event) {
          }, {passive: false} );
        </script>
        ```
        **逻辑推理 (假设输入与输出):**
        *   **假设输入:**  用户触摸了 `id="blocking"` 的 div 元素。
        *   **输出:**  由于 `passive: false`，浏览器会等待 Javascript 事件处理函数执行完毕后再决定是否滚动。在 Blink 内部，这会反映在合成层的 `touch_action_region` 上，该区域会标记为阻止触摸滚动。
    *   **举例:**  `wheelEventHandler` 测试用例加载了一个包含 `wheel` 事件监听器的 HTML 文件，用于测试鼠标滚轮事件的处理。
*   **HTML:**
    *   **举例:** `fastScrollingByDefault` 测试用例加载了一个简单的 HTML 结构，其中包含一个高度很高的 `div` 元素，以确保页面可以滚动。
        ```html
        <div id='spacer' style='height: 1000px'></div>
        ```
        **逻辑推理 (假设输入与输出):**
        *   **假设输入:** 用户打开包含上述 HTML 的页面。
        *   **输出:** Blink 渲染引擎会创建一个可滚动的视口。`fastScrollingByDefault` 测试会断言这个视口的滚动节点是合成的 (`ASSERT_COMPOSITED`)。
    *   **举例:**  许多测试用例都通过 `LoadHTML` 加载包含特定 HTML 结构的字符串，例如包含带有 `id` 属性的 `div` 元素，以便后续通过 Javascript 或 Blink 内部 API 进行操作和检查。
*   **CSS:**
    *   **举例:** `fastScrollingForFixedPosition` 测试用例加载了一个包含固定定位元素的 HTML 文件 (`fixed-position.html`)。该测试旨在验证固定定位元素的存在不会阻止页面进行合成器滚动。
    *   **举例:** `fastScrollingForStickyPosition` 测试用例使用了 `position: sticky` 的 CSS 属性，并验证了其滚动行为和相关的粘性约束属性。
        ```css
        #div-tl {
          position: sticky;
          top: 1px;
          left: 1px;
        }
        ```
        **逻辑推理 (假设输入与输出):**
        *   **假设输入:** 用户滚动包含带有 `position: sticky` 元素的页面。
        *   **输出:** Blink 会计算粘性元素应该停留的位置，并将其信息存储在合成层的 `StickyPositionConstraint` 中。`fastScrollingForStickyPosition` 测试会验证这些约束是否正确。
    *   **举例:** `touchAction` 测试用例使用 `touch-action` CSS 属性来控制元素的触摸行为。
        ```css
        #scrollable {
          touch-action: pan-x pan-down;
        }
        ```
        **逻辑推理 (假设输入与输出):**
        *   **假设输入:** 用户尝试在 `id="scrollable"` 的元素上进行触摸操作。
        *   **输出:**  由于 `touch-action: pan-x pan-down;`，用户只能水平或向下平移，其他类型的触摸操作可能会被浏览器阻止或以特定方式处理。在 Blink 内部，合成层的 `touch_action_region` 会反映这些限制。

**用户或编程常见的使用错误举例说明：**

*   **错误:**  在滚动容器上添加了 `touchstart` 或 `touchmove` 事件监听器，并且没有设置 `passive: true`。这会导致浏览器在每次触摸移动时都等待 Javascript 代码执行完毕，才能判断是否进行滚动，从而可能导致滚动不流畅。
    *   **调试线索:**  用户抱怨滚动卡顿。作为调试，开发者可能会查看 `scrolling_test.cc` 中类似 `touchEventHandler` 的测试用例，了解 Blink 如何处理这种情况，并验证自己的代码是否符合预期。他们可以使用 Chromium 的 DevTools 的 Performance 面板来分析滚动时的帧率和主线程活动。
*   **错误:**  错误地使用了 `touch-action` CSS 属性，导致某些触摸交互被意外禁用。例如，设置了 `touch-action: none` 可能会阻止元素响应任何触摸事件，包括点击。
    *   **调试线索:** 用户报告无法在某个元素上进行触摸交互。开发者可能会参考 `scrolling_test.cc` 中关于 `touchAction` 的测试用例，理解 `touch-action` 的各种取值及其效果，并检查元素的 CSS 样式。他们可以使用 DevTools 的 Elements 面板查看元素的样式和计算出的属性。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户遇到滚动问题:** 用户在使用 Chromium 浏览器浏览网页时，可能遇到了滚动不流畅、卡顿、或者触摸交互不符合预期的现象。
2. **开发者尝试复现问题:** 开发者尝试在自己的环境中复现用户报告的问题。
3. **分析网页结构和代码:** 开发者会检查出现问题的网页的 HTML 结构、CSS 样式以及 Javascript 代码，特别是与滚动相关的事件监听器和 CSS 属性。
4. **怀疑 Blink 引擎的滚动机制:** 如果开发者怀疑问题可能出在浏览器底层的滚动实现上，他们可能会开始查看 Chromium 的源代码，特别是 Blink 渲染引擎中负责处理滚动的部分。
5. **定位到 `scrolling_test.cc`:**  开发者可能会搜索与滚动相关的测试文件，找到 `blink/renderer/core/page/scrolling/scrolling_test.cc`。这个文件包含了大量的滚动相关的测试用例，可以帮助开发者理解 Blink 是如何处理各种滚动场景的。
6. **研究相关测试用例:**  开发者会找到与用户遇到的问题相似的测试用例，例如，如果用户报告触摸滚动卡顿，他们可能会查看 `touchEventHandler` 相关的测试。通过阅读测试代码和相关的注释，开发者可以更深入地理解 Blink 的滚动机制以及可能导致问题的原因。
7. **进行本地代码调试:**  开发者可能会在本地编译 Chromium，并运行相关的测试用例，甚至修改测试用例来模拟用户遇到的具体场景，以便进行更深入的调试和分析。

总而言之，`scrolling_test.cc` 的第一部分主要负责搭建测试框架，提供加载网页内容和访问 Blink 内部组件的工具，并包含了一系列测试用例，用于验证 Blink 引擎在处理各种滚动场景时的正确性和性能，涵盖了默认滚动行为、CSS 属性的影响以及 Javascript 事件处理器的交互。 它可以作为理解 Blink 滚动机制、排查滚动相关问题的良好起点。

### 提示词
```
这是目录为blink/renderer/core/page/scrolling/scrolling_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2012 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "base/test/scoped_feature_list.h"
#include "base/uuid.h"
#include "build/build_config.h"
#include "cc/animation/animation_host.h"
#include "cc/animation/keyframe_effect.h"
#include "cc/base/features.h"
#include "cc/input/main_thread_scrolling_reason.h"
#include "cc/layers/scrollbar_layer_base.h"
#include "cc/trees/compositor_commit_data.h"
#include "cc/trees/layer_tree_impl.h"
#include "cc/trees/property_tree.h"
#include "cc/trees/scroll_node.h"
#include "cc/trees/single_thread_proxy.h"
#include "cc/trees/sticky_position_constraint.h"
#include "content/test/test_blink_web_unit_test_support.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/web_cache.h"
#include "third_party/blink/public/web/web_settings.h"
#include "third_party/blink/public/web/web_view_client.h"
#include "third_party/blink/renderer/core/css/css_style_sheet.h"
#include "third_party/blink/renderer/core/css/style_sheet_list.h"
#include "third_party/blink/renderer/core/dom/events/add_event_listener_options_resolved.h"
#include "third_party/blink/renderer/core/dom/events/native_event_listener.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/exported/web_plugin_container_impl.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/html/html_iframe_element.h"
#include "third_party/blink/renderer/core/html/html_object_element.h"
#include "third_party/blink/renderer/core/layout/layout_embedded_content.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/page/focus_controller.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/scrolling/scrolling_coordinator.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/animation/compositor_animation.h"
#include "third_party/blink/renderer/platform/graphics/gpu/shared_gpu_context.h"
#include "third_party/blink/renderer/platform/graphics/test/fake_gles2_interface.h"
#include "third_party/blink/renderer/platform/graphics/test/fake_web_graphics_context_3d_provider.h"
#include "third_party/blink/renderer/platform/graphics/touch_action.h"
#include "third_party/blink/renderer/platform/region_capture_crop_id.h"
#include "third_party/blink/renderer/platform/scheduler/public/main_thread_scheduler.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread_scheduler.h"
#include "third_party/blink/renderer/platform/testing/find_cc_layer.h"
#include "third_party/blink/renderer/platform/testing/paint_test_configurations.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/url_loader_mock_factory.h"
#include "third_party/blink/renderer/platform/testing/url_test_helpers.h"
#include "ui/base/ui_base_features.h"
#include "ui/gfx/geometry/point.h"
#include "ui/gfx/geometry/rect.h"

namespace blink {

namespace {

constexpr char kHttpBaseUrl[] = "http://www.test.com/";
constexpr char kHttpsBaseUrl[] = "https://www.test.com/";

cc::Region RegionFromRects(std::initializer_list<gfx::Rect> rects) {
  cc::Region region;
  for (const auto& rect : rects) {
    region.Union(rect);
  }
  return region;
}

}  // namespace

class ScrollingTest : public testing::Test, public PaintTestConfigurations {
 public:
  ScrollingTest() {
    helper_.Initialize();
    SetPreferCompositingToLCDText(true);
    GetWebView()->MainFrameViewWidget()->Resize(gfx::Size(320, 240));
    GetWebView()->MainFrameViewWidget()->UpdateAllLifecyclePhases(
        DocumentUpdateReason::kTest);
  }

  ~ScrollingTest() override {
    url_test_helpers::UnregisterAllURLsAndClearMemoryCache();
  }

  void NavigateToHttp(const std::string& url_fragment) {
    frame_test_helpers::LoadFrame(GetWebView()->MainFrameImpl(),
                                  kHttpBaseUrl + url_fragment);
  }

  void NavigateToHttps(const std::string& url_fragment) {
    frame_test_helpers::LoadFrame(GetWebView()->MainFrameImpl(),
                                  kHttpsBaseUrl + url_fragment);
  }

  void LoadHTML(const std::string& html) {
    frame_test_helpers::LoadHTMLString(GetWebView()->MainFrameImpl(), html,
                                       url_test_helpers::ToKURL("about:blank"));
  }

  void ForceFullCompositingUpdate() {
    GetWebView()->MainFrameViewWidget()->UpdateAllLifecyclePhases(
        DocumentUpdateReason::kTest);
  }

  void RegisterMockedHttpURLLoad(const std::string& file_name) {
    // TODO(crbug.com/751425): We should use the mock functionality
    // via |helper_|.
    url_test_helpers::RegisterMockedURLLoadFromBase(
        WebString::FromUTF8(kHttpBaseUrl), test::CoreTestDataPath(),
        WebString::FromUTF8(file_name));
  }

  void RegisterMockedHttpsURLLoad(const std::string& file_name) {
    // TODO(crbug.com/751425): We should use the mock functionality
    // via |helper_|.
    url_test_helpers::RegisterMockedURLLoadFromBase(
        WebString::FromUTF8(kHttpsBaseUrl), test::CoreTestDataPath(),
        WebString::FromUTF8(file_name));
  }

  void SetupHttpTestURL(const std::string& url_fragment) {
    RegisterMockedHttpURLLoad(url_fragment);
    NavigateToHttp(url_fragment);
    ForceFullCompositingUpdate();
  }

  void SetupHttpsTestURL(const std::string& url_fragment) {
    RegisterMockedHttpsURLLoad(url_fragment);
    NavigateToHttps(url_fragment);
    ForceFullCompositingUpdate();
  }

  WebViewImpl* GetWebView() const { return helper_.GetWebView(); }
  LocalFrame* GetFrame() const { return helper_.LocalMainFrame()->GetFrame(); }

  frame_test_helpers::TestWebFrameWidget* GetMainFrameWidget() const {
    return helper_.GetMainFrameWidget();
  }

  PaintLayerScrollableArea* ScrollableAreaByDOMElementId(
      const char* id_value) const {
    return GetFrame()
        ->GetDocument()
        ->getElementById(AtomicString(id_value))
        ->GetLayoutBoxForScrolling()
        ->GetScrollableArea();
  }

  void LoadAhem() { helper_.LoadAhem(); }

  cc::ScrollNode* ScrollNodeForScrollableArea(
      const ScrollableArea* scrollable_area) {
    if (!scrollable_area)
      return nullptr;
    auto* property_trees = RootCcLayer()->layer_tree_host()->property_trees();
    return property_trees->scroll_tree_mutable().FindNodeFromElementId(
        scrollable_area->GetScrollElementId());
  }

  cc::ScrollNode* ScrollNodeByDOMElementId(const char* dom_id) {
    return ScrollNodeForScrollableArea(ScrollableAreaByDOMElementId(dom_id));
  }

  gfx::PointF CurrentScrollOffset(cc::ElementId element_id) const {
    return RootCcLayer()
        ->layer_tree_host()
        ->property_trees()
        ->scroll_tree()
        .current_scroll_offset(element_id);
  }

  gfx::PointF CurrentScrollOffset(const cc::ScrollNode* scroll_node) const {
    return CurrentScrollOffset(scroll_node->element_id);
  }

  cc::ScrollbarLayerBase* ScrollbarLayerForScrollNode(
      cc::ScrollNode* scroll_node,
      cc::ScrollbarOrientation orientation) {
    return blink::ScrollbarLayerForScrollNode(RootCcLayer(), scroll_node,
                                              orientation);
  }

  cc::Layer* RootCcLayer() { return GetFrame()->View()->RootCcLayer(); }

  const cc::Layer* RootCcLayer() const {
    return GetFrame()->View()->RootCcLayer();
  }

  cc::LayerTreeHost* LayerTreeHost() { return helper_.GetLayerTreeHost(); }

  const cc::Layer* FrameScrollingContentsLayer(const LocalFrame& frame) const {
    return ScrollingContentsCcLayerByScrollElementId(
        RootCcLayer(), frame.View()->LayoutViewport()->GetScrollElementId());
  }

  const cc::Layer* MainFrameScrollingContentsLayer() const {
    return FrameScrollingContentsLayer(*GetFrame());
  }

  const cc::Layer* LayerByDOMElementId(const char* dom_id) const {
    return CcLayersByDOMElementId(RootCcLayer(), dom_id)[0];
  }

  const cc::Layer* ScrollingContentsLayerByDOMElementId(
      const char* element_id) const {
    const auto* scrollable_area = ScrollableAreaByDOMElementId(element_id);
    return ScrollingContentsCcLayerByScrollElementId(
        RootCcLayer(), scrollable_area->GetScrollElementId());
  }

  void SetPreferCompositingToLCDText(bool enabled) {
    GetFrame()->GetSettings()->SetPreferCompositingToLCDTextForTesting(enabled);
  }

 private:
  void NavigateTo(const std::string& url) {
    frame_test_helpers::LoadFrame(GetWebView()->MainFrameImpl(), url);
  }

  test::TaskEnvironment task_environment_;
  frame_test_helpers::WebViewHelper helper_;
};

INSTANTIATE_PAINT_TEST_SUITE_P(ScrollingTest);

#define ASSERT_COMPOSITED(scroll_node)                            \
  do {                                                            \
    ASSERT_TRUE(scroll_node);                                     \
    ASSERT_TRUE(scroll_node->is_composited);                      \
    EXPECT_EQ(cc::MainThreadScrollingReason::kNotScrollingOnMain, \
              scroll_node->main_thread_repaint_reasons);          \
  } while (false)

#define ASSERT_NOT_COMPOSITED(scroll_node,                          \
                              expected_main_thread_repaint_reasons) \
  do {                                                              \
    ASSERT_TRUE(scroll_node);                                       \
    ASSERT_FALSE(scroll_node->is_composited);                       \
    EXPECT_EQ(expected_main_thread_repaint_reasons,                 \
              scroll_node->main_thread_repaint_reasons);            \
  } while (false)

TEST_P(ScrollingTest, fastScrollingByDefault) {
  GetWebView()->MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  LoadHTML("<div id='spacer' style='height: 1000px'></div>");
  ForceFullCompositingUpdate();

  // Make sure the scrolling coordinator is active.
  LocalFrameView* frame_view = GetFrame()->View();
  Page* page = GetFrame()->GetPage();
  ASSERT_TRUE(page->GetScrollingCoordinator());

  // Fast scrolling should be enabled by default.
  const auto* outer_scroll_node =
      ScrollNodeForScrollableArea(frame_view->LayoutViewport());
  ASSERT_COMPOSITED(outer_scroll_node);

  ASSERT_EQ(cc::EventListenerProperties::kNone,
            LayerTreeHost()->event_listener_properties(
                cc::EventListenerClass::kTouchStartOrMove));
  ASSERT_EQ(cc::EventListenerProperties::kNone,
            LayerTreeHost()->event_listener_properties(
                cc::EventListenerClass::kMouseWheel));

  const auto* inner_scroll_node =
      ScrollNodeForScrollableArea(&page->GetVisualViewport());
  ASSERT_COMPOSITED(inner_scroll_node);
}

TEST_P(ScrollingTest, fastFractionalScrollingDiv) {
  ScopedFractionalScrollOffsetsForTest fractional_scroll_offsets(true);

  SetupHttpTestURL("fractional-scroll-div.html");

  Document* document = GetFrame()->GetDocument();
  Element* scrollable_element =
      document->getElementById(AtomicString("scroller"));
  DCHECK(scrollable_element);

  scrollable_element->setScrollTop(1.0);
  scrollable_element->setScrollLeft(1.0);
  ForceFullCompositingUpdate();

  // Make sure the fractional scroll offset change 1.0 -> 1.2 gets propagated
  // to compositor.
  scrollable_element->setScrollTop(1.2);
  scrollable_element->setScrollLeft(1.2);
  ForceFullCompositingUpdate();

  const auto* scroll_node = ScrollNodeByDOMElementId("scroller");
  ASSERT_TRUE(scroll_node);
  ASSERT_NEAR(1.2f, CurrentScrollOffset(scroll_node).x(), 0.01f);
  ASSERT_NEAR(1.2f, CurrentScrollOffset(scroll_node).y(), 0.01f);
}

TEST_P(ScrollingTest, fastScrollingForFixedPosition) {
  SetupHttpTestURL("fixed-position.html");

  const auto* scroll_node =
      ScrollNodeForScrollableArea(GetFrame()->View()->LayoutViewport());
  ASSERT_TRUE(scroll_node);
  EXPECT_FALSE(scroll_node->main_thread_repaint_reasons);
}

// Sticky constraints are stored on transform property tree nodes.
static cc::StickyPositionConstraint GetStickyConstraint(Element* element) {
  const auto* properties =
      element->GetLayoutObject()->FirstFragment().PaintProperties();
  DCHECK(properties);
  return *properties->StickyTranslation()->GetStickyConstraint();
}

TEST_P(ScrollingTest, fastScrollingForStickyPosition) {
  SetupHttpTestURL("sticky-position.html");

  // Sticky position should not fall back to main thread scrolling.
  const auto* scroll_node =
      ScrollNodeForScrollableArea(GetFrame()->View()->LayoutViewport());
  ASSERT_COMPOSITED(scroll_node);

  Document* document = GetFrame()->GetDocument();
  {
    Element* element = document->getElementById(AtomicString("div-tl"));
    auto constraint = GetStickyConstraint(element);
    EXPECT_TRUE(constraint.is_anchored_top && constraint.is_anchored_left &&
                !constraint.is_anchored_right &&
                !constraint.is_anchored_bottom);
    EXPECT_EQ(1.f, constraint.top_offset);
    EXPECT_EQ(1.f, constraint.left_offset);
    EXPECT_EQ(gfx::RectF(100, 100, 10, 10),
              constraint.scroll_container_relative_sticky_box_rect);
    EXPECT_EQ(gfx::RectF(100, 100, 200, 200),
              constraint.scroll_container_relative_containing_block_rect);
  }
  {
    Element* element = document->getElementById(AtomicString("div-tr"));
    auto constraint = GetStickyConstraint(element);
    EXPECT_TRUE(constraint.is_anchored_top && !constraint.is_anchored_left &&
                constraint.is_anchored_right && !constraint.is_anchored_bottom);
  }
  {
    Element* element = document->getElementById(AtomicString("div-bl"));
    auto constraint = GetStickyConstraint(element);
    EXPECT_TRUE(!constraint.is_anchored_top && constraint.is_anchored_left &&
                !constraint.is_anchored_right && constraint.is_anchored_bottom);
  }
  {
    Element* element = document->getElementById(AtomicString("div-br"));
    auto constraint = GetStickyConstraint(element);
    EXPECT_TRUE(!constraint.is_anchored_top && !constraint.is_anchored_left &&
                constraint.is_anchored_right && constraint.is_anchored_bottom);
  }
  {
    Element* element = document->getElementById(AtomicString("span-tl"));
    auto constraint = GetStickyConstraint(element);
    EXPECT_TRUE(constraint.is_anchored_top && constraint.is_anchored_left &&
                !constraint.is_anchored_right &&
                !constraint.is_anchored_bottom);
  }
  {
    Element* element = document->getElementById(AtomicString("span-tlbr"));
    auto constraint = GetStickyConstraint(element);
    EXPECT_TRUE(constraint.is_anchored_top && constraint.is_anchored_left &&
                constraint.is_anchored_right && constraint.is_anchored_bottom);
    EXPECT_EQ(1.f, constraint.top_offset);
    EXPECT_EQ(1.f, constraint.left_offset);
    EXPECT_EQ(1.f, constraint.right_offset);
    EXPECT_EQ(1.f, constraint.bottom_offset);
  }
  {
    Element* element = document->getElementById(AtomicString("composited-top"));
    auto constraint = GetStickyConstraint(element);
    EXPECT_TRUE(constraint.is_anchored_top);
    EXPECT_EQ(gfx::RectF(100, 110, 10, 10),
              constraint.scroll_container_relative_sticky_box_rect);
    EXPECT_EQ(gfx::RectF(100, 100, 200, 200),
              constraint.scroll_container_relative_containing_block_rect);
  }
}

TEST_P(ScrollingTest, elementPointerEventHandler) {
  LoadHTML(R"HTML(
    <div id="pointer" style="width: 100px; height: 100px;"></div>
    <script>
      pointer.addEventListener('pointerdown', function(event) {
      }, {blocking: false} );
    </script>
  )HTML");
  ForceFullCompositingUpdate();

  const auto* cc_layer = MainFrameScrollingContentsLayer();

  // Pointer event handlers should not generate blocking touch action regions.
  cc::Region region = cc_layer->touch_action_region().GetRegionForTouchAction(
      TouchAction::kNone);
  EXPECT_TRUE(region.IsEmpty());
}

TEST_P(ScrollingTest, touchEventHandler) {
  SetupHttpTestURL("touch-event-handler.html");

  ASSERT_EQ(cc::EventListenerProperties::kBlocking,
            LayerTreeHost()->event_listener_properties(
                cc::EventListenerClass::kTouchStartOrMove));
}

TEST_P(ScrollingTest, elementBlockingTouchEventHandler) {
  LoadHTML(R"HTML(
    <div id="blocking" style="width: 100px; height: 100px;"></div>
    <script>
      blocking.addEventListener('touchstart', function(event) {
      }, {passive: false} );
    </script>
  )HTML");
  ForceFullCompositingUpdate();

  const auto* cc_layer = MainFrameScrollingContentsLayer();
  cc::Region region = cc_layer->touch_action_region().GetRegionForTouchAction(
      TouchAction::kNone);
  EXPECT_EQ(cc::Region(gfx::Rect(8, 8, 100, 100)), region);
}

TEST_P(ScrollingTest, touchEventHandlerPassive) {
  SetupHttpTestURL("touch-event-handler-passive.html");

  ASSERT_EQ(cc::EventListenerProperties::kPassive,
            LayerTreeHost()->event_listener_properties(
                cc::EventListenerClass::kTouchStartOrMove));
}

TEST_P(ScrollingTest, elementTouchEventHandlerPassive) {
  LoadHTML(R"HTML(
    <div id="passive" style="width: 100px; height: 100px;"></div>
    <script>
      passive.addEventListener('touchstart', function(event) {
      }, {passive: true} );
    </script>
  )HTML");
  ForceFullCompositingUpdate();

  const auto* cc_layer = MainFrameScrollingContentsLayer();

  // Passive event handlers should not generate blocking touch action regions.
  cc::Region region = cc_layer->touch_action_region().GetRegionForTouchAction(
      TouchAction::kNone);
  EXPECT_TRUE(region.IsEmpty());
}

TEST_P(ScrollingTest, TouchActionRectsOnImage) {
  LoadHTML(R"HTML(
    <img id="image" style="width: 100px; height: 100px; touch-action: none;">
  )HTML");
  ForceFullCompositingUpdate();

  const auto* cc_layer = MainFrameScrollingContentsLayer();
  cc::Region region = cc_layer->touch_action_region().GetRegionForTouchAction(
      TouchAction::kNone);
  EXPECT_EQ(cc::Region(gfx::Rect(8, 8, 100, 100)), region);
}

TEST_P(ScrollingTest, touchEventHandlerBoth) {
  SetupHttpTestURL("touch-event-handler-both.html");

  ASSERT_EQ(cc::EventListenerProperties::kBlockingAndPassive,
            LayerTreeHost()->event_listener_properties(
                cc::EventListenerClass::kTouchStartOrMove));
}

TEST_P(ScrollingTest, wheelEventHandler) {
  SetupHttpTestURL("wheel-event-handler.html");

  ASSERT_EQ(cc::EventListenerProperties::kBlocking,
            LayerTreeHost()->event_listener_properties(
                cc::EventListenerClass::kMouseWheel));
}

TEST_P(ScrollingTest, wheelEventHandlerPassive) {
  SetupHttpTestURL("wheel-event-handler-passive.html");

  ASSERT_EQ(cc::EventListenerProperties::kPassive,
            LayerTreeHost()->event_listener_properties(
                cc::EventListenerClass::kMouseWheel));
}

TEST_P(ScrollingTest, wheelEventHandlerBoth) {
  SetupHttpTestURL("wheel-event-handler-both.html");

  ASSERT_EQ(cc::EventListenerProperties::kBlockingAndPassive,
            LayerTreeHost()->event_listener_properties(
                cc::EventListenerClass::kMouseWheel));
}

TEST_P(ScrollingTest, scrollEventHandler) {
  SetupHttpTestURL("scroll-event-handler.html");

  ASSERT_TRUE(GetMainFrameWidget()->HaveScrollEventHandlers());
}

TEST_P(ScrollingTest, updateEventHandlersDuringTeardown) {
  SetupHttpTestURL("scroll-event-handler-window.html");

  // Simulate detaching the document from its DOM window. This should not
  // cause a crash when the WebViewImpl is closed by the test runner.
  GetFrame()->GetDocument()->Shutdown();
}

TEST_P(ScrollingTest, clippedBodyTest) {
  SetupHttpTestURL("clipped-body.html");

  const auto* root_scroll_layer = MainFrameScrollingContentsLayer();
  EXPECT_TRUE(
      root_scroll_layer->main_thread_scroll_hit_test_region().IsEmpty());
  EXPECT_FALSE(root_scroll_layer->non_composited_scroll_hit_test_rects());
}

TEST_P(ScrollingTest, touchAction) {
  SetupHttpTestURL("touch-action.html");

  const auto* cc_layer = ScrollingContentsLayerByDOMElementId("scrollable");
  cc::Region region = cc_layer->touch_action_region().GetRegionForTouchAction(
      TouchAction::kPanX | TouchAction::kPanDown |
      TouchAction::kInternalPanXScrolls | TouchAction::kInternalNotWritable);
  EXPECT_EQ(cc::Region(gfx::Rect(0, 0, 1000, 1000)), region);
}

TEST_P(ScrollingTest, touchActionRegions) {
  SetupHttpTestURL("touch-action-regions.html");

  const auto* cc_layer = ScrollingContentsLayerByDOMElementId("scrollable");

  cc::Region region = cc_layer->touch_action_region().GetRegionForTouchAction(
      TouchAction::kPanDown | TouchAction::kPanX |
      TouchAction::kInternalPanXScrolls | TouchAction::kInternalNotWritable);
  EXPECT_EQ(cc::Region(gfx::Rect(0, 0, 100, 100)), region);

  region = cc_layer->touch_action_region().GetRegionForTouchAction(
      TouchAction::kPanDown | TouchAction::kPanRight |
      TouchAction::kInternalPanXScrolls | TouchAction::kInternalNotWritable);
  EXPECT_EQ(cc::Region(gfx::Rect(0, 0, 50, 50)), region);

  region = cc_layer->touch_action_region().GetRegionForTouchAction(
      TouchAction::kPanDown | TouchAction::kInternalNotWritable);
  EXPECT_EQ(cc::Region(gfx::Rect(0, 100, 100, 100)), region);
}

TEST_P(ScrollingTest, touchActionNesting) {
  LoadHTML(R"HTML(
    <style>
      #scrollable {
        width: 200px;
        height: 200px;
        background: blue;
        overflow: scroll;
      }
      #touchaction {
        touch-action: pan-x;
        width: 100px;
        height: 100px;
        margin: 5px;
      }
      #child {
        width: 150px;
        height: 50px;
      }
    </style>
    <div id="scrollable">
      <div id="touchaction">
        <div id="child"></div>
      </div>
      <div id="forcescroll" style="width: 1000px; height: 1000px;"></div>
    </div>
  )HTML");
  ForceFullCompositingUpdate();

  const auto* cc_layer = ScrollingContentsLayerByDOMElementId("scrollable");

  cc::Region region = cc_layer->touch_action_region().GetRegionForTouchAction(
      TouchAction::kPanX | TouchAction::kInternalPanXScrolls |
      TouchAction::kInternalNotWritable);
  EXPECT_EQ(
      RegionFromRects({gfx::Rect(5, 5, 150, 50), gfx::Rect(5, 55, 100, 50)}),
      region);
}

TEST_P(ScrollingTest, nestedTouchActionInvalidation) {
  LoadHTML(R"HTML(
    <style>
      #scrollable {
        width: 200px;
        height: 200px;
        background: blue;
        overflow: scroll;
      }
      #touchaction {
        touch-action: pan-x;
        width: 100px;
        height: 100px;
        margin: 5px;
      }
      #child {
        width: 150px;
        height: 50px;
      }
    </style>
    <div id="scrollable">
      <div id="touchaction">
        <div id="child"></div>
      </div>
      <div id="forcescroll" style="width: 1000px; height: 1000px;"></div>
    </div>
  )HTML");
  ForceFullCompositingUpdate();

  const auto* cc_layer = ScrollingContentsLayerByDOMElementId("scrollable");

  cc::Region region = cc_layer->touch_action_region().GetRegionForTouchAction(
      TouchAction::kPanX | TouchAction::kInternalPanXScrolls |
      TouchAction::kInternalNotWritable);
  EXPECT_EQ(
      RegionFromRects({gfx::Rect(5, 5, 150, 50), gfx::Rect(5, 55, 100, 50)}),
      region);

  auto* scrollable =
      GetFrame()->GetDocument()->getElementById(AtomicString("scrollable"));
  scrollable->setAttribute(html_names::kStyleAttr,
                           AtomicString("touch-action: none"));
  ForceFullCompositingUpdate();
  region = cc_layer->touch_action_region().GetRegionForTouchAction(
      TouchAction::kPanX | TouchAction::kInternalPanXScrolls |
      TouchAction::kInternalNotWritable);
  EXPECT_TRUE(region.IsEmpty());
}

// Similar to nestedTouchActionInvalidation but tests that an ancestor with
// touch-action: pan-x and a descendant with touch-action: pan-y results in a
// touch-action rect of none for the descendant.
TEST_P(ScrollingTest, nestedTouchActionChangesUnion) {
  LoadHTML(R"HTML(
    <style>
      #ancestor {
        width: 100px;
        height: 100px;
      }
      #child {
        touch-action: pan-x;
        width: 150px;
        height: 50px;
      }
    </style>
    <div id="ancestor">
      <div id="child"></div>
    </div>
  )HTML");
  ForceFullCompositingUpdate();

  const auto* cc_layer = MainFrameScrollingContentsLayer();

  cc::Region region = cc_layer->touch_action_region().GetRegionForTouchAction(
      TouchAction::kPanX | TouchAction::kInternalPanXScrolls |
      TouchAction::kInternalNotWritable);
  EXPECT_EQ(cc::Region(gfx::Rect(8, 8, 150, 50)), region);
  region = cc_layer->touch_action_region().GetRegionForTouchAction(
      TouchAction::kNone);
  EXPECT_TRUE(region.IsEmpty());

  Element* ancestor =
      GetFrame()->GetDocument()->getElementById(AtomicString("ancestor"));
  ancestor->setAttribute(html_names::kStyleAttr,
                         AtomicString("touch-action: pan-y"));
  ForceFullCompositingUpdate();

  region = cc_layer->touch_action_region().GetRegionForTouchAction(
      TouchAction::kPanY | TouchAction::kInternalNotWritable);
  EXPECT_EQ(cc::Region(gfx::Rect(8, 8, 100, 100)), region);
  region = cc_layer->touch_action_region().GetRegionForTouchAction(
      TouchAction::kPanX | TouchAction::kInternalPanXScrolls |
      TouchAction::kInternalNotWritable);
  EXPECT_TRUE(region.IsEmpty());
  // kInternalNotWritable is set when any of the pans are allowed.
  region = cc_layer->touch_action_region().GetRegionForTouchAction(
      TouchAction::kNone | TouchAction::kInternalNotWritable);
  EXPECT_EQ(cc::Region(gfx::Rect(8, 8, 150, 50)), region);
}

TEST_P(ScrollingTest, touchActionEditableElement) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitWithFeatures({::features::kSwipeToMoveCursor}, {});
  if (!::features::IsSwipeToMoveCursorEnabled())
    return;
  // Long text that will overflow in y-direction.
  LoadHTML(R"HTML(
    <style>
      #touchaction {
        touch-action: manipulation;
        width: 100px;
        height: 50px;
        overflow: scroll;
      }
    </style>
    <div id="touchaction" contenteditable>
      <div id="child"></div>
    </div>
  )HTML");
  ForceFullCompositingUpdate();
  const auto* cc_layer = MainFrameScrollingContentsLayer();
  cc::Region region = cc_layer->touch_action_region().GetRegionForTouchAction(
      TouchAction::kManipulation | TouchAction::kInternalNotWritable);
  EXPECT_EQ(cc::Region(gfx::Rect(8, 8, 100, 50)), region);
  region = cc_layer->touch_action_region().GetRegionForTouchAction(
      TouchAction::kNone);
  EXPECT_TRUE(region.IsEmpty());

  // Make touchaction scrollable by making child overflow.
  Element* child =
      GetFrame()->GetDocument()->getElementById(AtomicString("child"));
  child->setAttribute(html_names::kStyleAttr,
                      AtomicString("width: 1000px; height: 100px;"));
  ForceFullCompositingUpdate();

  cc_layer = ScrollingContentsLayerByDOMElementId("touchaction");
  region = cc_layer->touch_action_region().GetRegionForTouchAction(
      TouchAction::kManipulation | TouchAction::kInternalPanXScrolls |
      TouchAction::kInternalNotWritable);
  EXPECT_EQ(cc::Region(gfx::Rect(0, 0, 1000, 100)), region);
  region = cc_layer->touch_action_region().GetRegionForTouchAction(
      TouchAction::kNone);
  EXPECT_TRUE(region.IsEmpty());
}

// Box shadow is not hit testable and should not be included in touch action.
TEST_P(ScrollingTest, touchActionExcludesBoxShadow) {
  LoadHTML(R"HTML(
    <style>
      #shadow {
        width: 100px;
        height: 100px;
        touch-action: none;
        box-shadow: 10px 5px 5px red;
      }
    </style>
    <div id="shadow"></div>
  )HTML");
  ForceFullCompositingUpdate();

  const auto* cc_layer = MainFrameScrollingContentsLayer();

  cc::Region region = cc_layer->touch_action_region().GetRegionForTouchAction(
      TouchAction::kNone);
  EXPECT_EQ(cc::Region(gfx::Rect(8, 8, 100, 100)), region);
}

TEST_P(ScrollingTest, touchActionOnInline) {
  RegisterMockedHttpURLLoad("touch-action-on-inline.html");
  NavigateToHttp("touch-action-on-inline.html");
  LoadAhem();
  ForceFullCompositingUpdate();

  const auto* cc_layer = MainFrameScrollingContentsLayer();

  cc::Region region = cc_layer->touch_action_region().GetRegionForTouchAction(
      TouchAction::kNone);
  EXPECT_EQ(
      RegionFromRects({gfx::Rect(8, 8, 120, 10), gfx::Rect(8, 18, 10, 40)}),
      region);
}

TEST_P(ScrollingTest, touchActionOnText) {
  RegisterMockedHttpURLLoad("touch-action-on-text.html");
  NavigateToHttp("touch-action-on-text.html");
  LoadAhem();
  ForceFullCompositingUpdate();

  const auto* cc_layer = MainFrameScrollingContentsLayer();

  cc::Region region = cc_layer->touch_action_region().GetRegionForTouchAction(
      TouchAction::kNone);
  EXPECT_EQ(RegionFromRects({gfx::Rect(8, 8, 80, 10), gfx::Rect(8, 18, 40, 10),
                             gfx::Rect(8, 28, 160, 10)}),
            region);
}

TEST_P(ScrollingTest, touchActionWithVerticalRLWritingMode) {
  RegisterMockedHttpURLLoad("touch-action-with-vertical-rl-writing-mode.html");
  NavigateToHttp("touch-action-with-vertical-rl-writing-mode.html");
  LoadAhem();
  ForceFullCompositingUpdate();

  const auto* cc_layer = MainFrameScrollingContentsLayer();

  cc::Region region = cc_layer->touch_action_region().GetRegionForTouchAction(
      TouchAction::kNone);
  EXPECT_EQ(
      RegionFromRects({gfx::Rect(292, 8, 20, 20), gfx::Rect(302, 28, 10, 60)}),
      region);
}

TEST_P(ScrollingTest, touchActionBlockingHandler) {
  SetupHttpTestURL("touch-action-blocking-handler.html");

  const auto* cc_layer = ScrollingContentsLayerByDOMElementId("scrollable");

  cc::Region region = cc_layer->touch_action_region().GetRegionForTouchAction(
      TouchAction::kNone);
  EXPECT_EQ(cc::Region(gfx::Rect(0, 0, 100, 100)), region);

  region = cc_layer->touch_action_region().GetRegionForTouchAction(
      TouchAction::kPanY | TouchAction::kInternalNotWritable);
  EXPECT_EQ(RegionFromRects(
                {gfx::Rect(0, 0, 200, 100), gfx::Rect(0, 100, 1000, 900)}),
            region);
}

TEST_P(ScrollingTest, touchActionOnScrollingElement) {
  LoadHTML(R"HTML(
    <style>
      #scrollable {
        width: 100px;
        height: 100px;
        overflow: scroll;
        touch-action: pan-y;
      }
      #child {
        width: 50px;
        height: 150px;
      }
    </style>
    <div id="scrollable">
      <div id="child"></div>
    </div>
  )HTML");
  ForceFullCompositingUpdate();

  // The scrolling contents layer is fully marked as pan-y.
  const auto* scrolling_contents_layer =
      ScrollingContentsLayerByDOMElementId("scrollable");
  cc::Region region =
      scrolling_contents_layer->touch_action_region().GetRegionForTouchAction(
          TouchAction::kPanY | TouchAction::kInternalNotWritable);
  if (RuntimeEnabledFeatures::HitTestOpaquenessEnabled()) {
    EXPECT_EQ(scrolling_contents_layer->boun
```