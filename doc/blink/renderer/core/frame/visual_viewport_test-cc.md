Response:
The user wants a summary of the functionality of the provided C++ source code file `visual_viewport_test.cc`. This file appears to be a unit test for the `VisualViewport` class in the Chromium Blink rendering engine.

Here's a breakdown of the request and how to address it:

1. **List the functionality:**  I need to analyze the code and identify the core functionalities being tested. This involves looking at the test cases (functions starting with `TEST_P`) and the setup code.

2. **Relationship to JavaScript, HTML, CSS:**  I need to determine if the tested functionalities directly or indirectly relate to web development technologies. This can be inferred from the included headers and the nature of the tests.

3. **Examples for JavaScript, HTML, CSS:** If there's a relationship, I need to provide concrete examples of how these technologies interact with the `VisualViewport`.

4. **Logical Reasoning (Input/Output):** Some tests might involve manipulating the viewport and asserting the resulting state. For these, I can describe the assumed input and expected output.

5. **Common Usage Errors:** I should consider scenarios where developers might misuse or misunderstand the behavior of the `VisualViewport` and provide examples of such errors.

6. **Summarize Functionality (Part 1):** Finally, I need to condense the findings into a concise summary for the first part of the response.

**Mental Sandbox:**

* **Test Case Identification:** I see test cases like `TestResize`, `TestVisibleContentRect`, `TestResizeAfterVerticalScroll`, etc. These suggest testing different aspects of viewport manipulation.
* **Header Analysis:**  Includes like `"third_party/blink/renderer/core/frame/visual_viewport.h"`, `"third_party/blink/public/web/web_settings.h"`, and `"third_party/blink/public/web/web_view_client.h"` indicate the testing context involves web page rendering and browser interactions.
* **JavaScript Interaction:**  Viewport manipulation can be triggered via JavaScript (e.g., `window.scrollTo()`, `window.resizeTo()`, the `viewport` meta tag).
* **HTML Interaction:** The `viewport` meta tag in HTML directly influences the initial state of the visual viewport.
* **CSS Interaction:** CSS properties like `zoom`, transforms, and viewport units (`vw`, `vh`) can affect the visual viewport.
* **Input/Output Examples:** For `TestResize`, the input would be resizing the browser window or programmatically setting the viewport size. The output would be the updated dimensions of the `VisualViewport` object.
* **Common Errors:**  Developers might make assumptions about the visual viewport size or position without considering the effects of scaling or browser controls.

**High-Level Plan:**

1. Identify the core functionalities tested in the provided code.
2. For each functionality, determine its relevance to JavaScript, HTML, and CSS.
3. Provide illustrative examples for each connection.
4. For tests involving logical transformations, describe input and expected output.
5. Identify potential user/programming errors related to these functionalities.
6. Write a summary of the identified functionalities.
```
这是目录为blink/renderer/core/frame/visual_viewport_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能
```

这个 C++ 文件 `visual_viewport_test.cc` 是 Chromium Blink 引擎中 `VisualViewport` 类的单元测试文件。它的主要功能是**测试 `VisualViewport` 类的各种功能和行为是否符合预期**。

以下是该文件测试的具体功能，以及它们与 JavaScript, HTML, CSS 的关系，逻辑推理和常见错误：

**功能列表:**

1. **调整 VisualViewport 大小:** 测试显式地设置 `VisualViewport` 的大小，以及当 WebView 大小改变时 `VisualViewport` 的大小是否会相应改变。
2. **获取可见内容区域 (visibleContentRect):** 测试在不同的缩放级别和滚动位置下，`VisualViewport` 计算出的可见内容区域是否正确，包括是否排除或包含滚动条。
3. **在完全滚动时调整大小:** 测试当页面完全滚动后，调整 WebView 大小时，`VisualViewport` 的位置是否保持用户可见的区域不变。
4. **缩放和滚动后的调整大小 (垂直和水平):** 测试在 `VisualViewport` 经过缩放和滚动后，再调整 WebView 大小时，`VisualViewport` 的大小、位置和缩放比例是否正确更新。
5. **获取可见矩形 (visibleRect):** 测试 `VisualViewport` 在不同的缩放级别和滚动位置下，返回的可见矩形是否准确。
6. **防止小数滚动偏移被覆盖:** 测试当设置小数的滚动偏移时，该偏移是否能被正确保留。
7. **限制滚动偏移:** 测试 `VisualViewport` 的滚动偏移是否被正确限制在主 Frame 的边界内，防止滚动超出内容范围。
8. **在调整大小时限制滚动偏移:** 测试当 `VisualViewport` 大小改变时，滚动偏移是否仍然被正确限制。
9. **在调整大小和缩放时限制滚动偏移:** 测试当 `VisualViewport` 同时进行大小调整和缩放时，滚动偏移是否仍然被正确限制。
10. **根据内容调整 FrameView 大小:** 测试在 Android 等设备上，`LocalFrameView` 的大小是否根据最小缩放比例或内容宽高比进行设置。
11. **根据最小缩放比例调整 FrameView 大小:** 测试在桌面环境下，`LocalFrameView` 的大小是否根据最小缩放比例进行设置。
12. **附加新的 FrameView 时设置内部滚动层大小:** 测试当附加新的 `FrameView` 时，内部滚动层的大小是否被正确重置。

**与 JavaScript, HTML, CSS 的关系及举例:**

* **JavaScript:**
    * **功能 1 (调整 VisualViewport 大小):** JavaScript 可以通过 `window.visualViewport.width` 和 `window.visualViewport.height` (只读) 获取当前大小，但无法直接设置其大小。然而，调整浏览器窗口大小会间接影响 `VisualViewport` 的大小。
        * **例子:**  虽然不能直接设置，但 JavaScript 可以监听 `resize` 事件来获取 `VisualViewport` 的变化：
          ```javascript
          window.visualViewport.addEventListener('resize', () => {
            console.log('VisualViewport width:', window.visualViewport.width);
            console.log('VisualViewport height:', window.visualViewport.height);
          });
          ```
    * **功能 2 (获取可见内容区域):** JavaScript 可以通过 `window.visualViewport.pageLeft`, `window.visualViewport.pageTop`, `window.visualViewport.width`, `window.visualViewport.height` 计算出可见内容区域。
        * **例子:**
          ```javascript
          console.log('Visible content left:', window.visualViewport.pageLeft);
          console.log('Visible content top:', window.visualViewport.pageTop);
          console.log('Visible content width:', window.visualViewport.width);
          console.log('Visible content height:', window.visualViewport.height);
          ```
    * **功能 5 (获取可见矩形):**  `window.visualViewport` 对象的属性 (如上例) 提供了获取可见矩形所需的信息。
    * **功能 6 (防止小数滚动偏移被覆盖):** JavaScript 可以使用 `window.scrollTo()` 或设置 `window.scrollX` 和 `window.scrollY` 为小数来实现滚动。浏览器需要正确处理这些小数偏移。
        * **例子:**
          ```javascript
          window.scrollTo(0, 10.5);
          ```
    * **功能 7, 8, 9 (限制滚动偏移):**  浏览器会限制 JavaScript 设置的滚动偏移，确保不会滚动超出内容边界。
        * **例子:** 如果内容高度只有 500px，尝试 `window.scrollTo(0, 1000)`，浏览器会将垂直滚动偏移限制在 500px。

* **HTML:**
    * **功能 10 (根据内容调整 FrameView 大小):** HTML 中的 `<meta name="viewport" content="width=device-width, initial-scale=1.0">` 等设置会影响初始的 `VisualViewport` 大小，进而影响 `LocalFrameView` 的大小。
        * **例子:**
          ```html
          <!DOCTYPE html>
          <html>
          <head>
            <meta name="viewport" content="width=500">
          </head>
          <body>
            <!-- 内容 -->
          </body>
          </html>
          ```
          在这个例子中，`width=500` 可能会影响 `LocalFrameView` 的初始宽度。

* **CSS:**
    * **功能 2 (获取可见内容区域):** CSS 的布局会影响滚动条的出现，从而影响可见内容区域。
    * **功能 5 (获取可见矩形):** CSS 的 `zoom` 属性会影响页面的缩放，进而影响 `VisualViewport` 的可见矩形。Viewport 单位 (`vw`, `vh`) 也与 `VisualViewport` 的大小相关。
        * **例子:**
          ```css
          body {
            zoom: 2.0; /* 会影响 VisualViewport 的可见区域 */
          }
          .element {
            width: 50vw; /* 元素的宽度是 VisualViewport 宽度的一半 */
          }
          ```

**逻辑推理 (假设输入与输出):**

* **功能 1 (调整 VisualViewport 大小):**
    * **假设输入:** WebView 的大小从 320x240 调整到 640x480。
    * **预期输出:**  `VisualViewport` 的大小也变为 640x480 (在没有其他因素影响的情况下)。

* **功能 3 (在完全滚动时调整大小):**
    * **假设输入:** 页面已完全滚动到右下角，WebView 的宽度缩小。
    * **预期输出:** `VisualViewport` 的位置会调整，以保持用户看到的页面内容区域基本不变。

* **功能 7 (限制滚动偏移):**
    * **假设输入:**  尝试将 `VisualViewport` 的水平滚动偏移设置为超出内容宽度的值。
    * **预期输出:** `VisualViewport` 的实际水平滚动偏移将被限制为内容宽度的最大值。

**用户或编程常见的使用错误:**

* **假设 `window.innerWidth` 和 `window.innerHeight` 等于 `VisualViewport` 的大小:**  在移动端，这些属性通常指的是布局视口 (layout viewport) 的大小，而不是视觉视口 (visual viewport) 的大小。开发者需要使用 `window.visualViewport` API 来获取视觉视口的准确信息。
* **直接操作 `VisualViewport` 的大小:**  开发者无法像操作 DOM 元素一样直接设置 `VisualViewport` 的大小。`VisualViewport` 的大小主要由浏览器窗口大小和缩放比例决定。
* **不考虑缩放对坐标的影响:**  在进行触摸事件处理或布局计算时，如果没有考虑页面的缩放比例，可能会导致坐标计算错误。`VisualViewport` 的 `scale` 属性提供了当前的缩放比例。
* **在 `scroll` 事件中过度操作 DOM:**  `VisualViewport` 的滚动事件会频繁触发，如果在事件处理函数中进行大量的 DOM 操作，可能会导致性能问题。

**功能归纳 (第 1 部分):**

该文件主要测试了 `VisualViewport` 类的基本属性和行为，包括 **大小调整**、**获取可见区域**（包括内容区域和矩形）、以及在各种场景下（如完全滚动、缩放）的 **大小调整后的状态保持**。这些测试确保了 `VisualViewport` 能够正确反映用户在屏幕上实际看到的内容区域，并能与 WebView 的大小变化协同工作。

### 提示词
```
这是目录为blink/renderer/core/frame/visual_viewport_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/frame/visual_viewport.h"

#include <memory>
#include <string>

#include "cc/layers/picture_layer.h"
#include "cc/layers/scrollbar_layer_base.h"
#include "cc/trees/property_tree.h"
#include "cc/trees/scroll_node.h"
#include "cc/trees/transform_node.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/context_menu_data/context_menu_data.h"
#include "third_party/blink/public/common/input/web_coalesced_input_event.h"
#include "third_party/blink/public/common/input/web_input_event.h"
#include "third_party/blink/public/common/widget/device_emulation_params.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/public/web/web_ax_context.h"
#include "third_party/blink/public/web/web_document.h"
#include "third_party/blink/public/web/web_local_frame_client.h"
#include "third_party/blink/public/web/web_script_source.h"
#include "third_party/blink/public/web/web_settings.h"
#include "third_party/blink/public/web/web_view_client.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/frame/browser_controls.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/web_frame_widget_impl.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/html/html_body_element.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html/html_html_element.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/paint/paint_and_raster_invalidation_test.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/scroll/scroll_into_view_util.h"
#include "third_party/blink/renderer/core/scroll/scrollbar_theme_overlay_mobile.h"
#include "third_party/blink/renderer/core/scroll/smooth_scroll_sequencer.h"
#include "third_party/blink/renderer/core/testing/color_scheme_helper.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/graphics/compositing/paint_artifact_compositor.h"
#include "third_party/blink/renderer/platform/graphics/compositor_element_id.h"
#include "third_party/blink/renderer/platform/graphics/paint/geometry_mapper.h"
#include "third_party/blink/renderer/platform/testing/find_cc_layer.h"
#include "third_party/blink/renderer/platform/testing/paint_property_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/paint_test_configurations.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/url_loader_mock_factory.h"
#include "third_party/blink/renderer/platform/testing/url_test_helpers.h"
#include "ui/accessibility/ax_mode.h"
#include "ui/gfx/geometry/test/geometry_util.h"
#include "ui/gfx/geometry/vector2d_conversions.h"

using testing::_;
using testing::PrintToString;
using testing::Mock;
using testing::UnorderedElementsAre;
using blink::url_test_helpers::ToKURL;

namespace blink {

::std::ostream& operator<<(::std::ostream& os, const ContextMenuData& data) {
  return os << "Context menu location: [" << data.mouse_position.x() << ", "
            << data.mouse_position.y() << "]";
}

namespace {

const cc::EffectNode* GetEffectNode(const cc::Layer* layer) {
  return layer->layer_tree_host()->property_trees()->effect_tree().Node(
      layer->effect_tree_index());
}

class VisualViewportTest : public testing::Test,
                           public PaintTestConfigurations {
 public:
  VisualViewportTest() : base_url_("http://www.test.com/") {}

  void InitializeWithDesktopSettings() {
    helper_.InitializeWithSettings(&ConfigureSettings);
    WebView()->SetDefaultPageScaleLimits(1, 4);
  }

  void InitializeWithAndroidSettings(
      void (*override_settings_func)(WebSettings*) = nullptr) {
    if (!override_settings_func)
      override_settings_func = &ConfigureAndroidSettings;
    helper_.InitializeWithSettings(override_settings_func);
    WebView()->SetDefaultPageScaleLimits(0.25f, 5);
  }

  ~VisualViewportTest() override {
    url_test_helpers::UnregisterAllURLsAndClearMemoryCache();
  }

  void NavigateTo(const std::string& url) {
    frame_test_helpers::LoadFrame(WebView()->MainFrameImpl(), url);
  }

  void UpdateAllLifecyclePhases() {
    WebView()->MainFrameViewWidget()->UpdateAllLifecyclePhases(
        DocumentUpdateReason::kTest);
  }

  void UpdateAllLifecyclePhasesExceptPaint() {
    WebView()->MainFrameViewWidget()->UpdateLifecycle(
        WebLifecycleUpdate::kPrePaint, DocumentUpdateReason::kTest);
  }

  PaintArtifactCompositor* paint_artifact_compositor() {
    LocalFrameView& frame_view = *WebView()->MainFrameImpl()->GetFrameView();
    return frame_view.GetPaintArtifactCompositor();
  }

  void ForceFullCompositingUpdate() { UpdateAllLifecyclePhases(); }

  void RegisterMockedHttpURLLoad(const std::string& fileName) {
    // TODO(crbug.com/751425): We should use the mock functionality
    // via |helper_|.
    url_test_helpers::RegisterMockedURLLoadFromBase(
        WebString::FromUTF8(base_url_), blink::test::CoreTestDataPath(),
        WebString::FromUTF8(fileName));
  }

  void RegisterMockedHttpURLLoad(const std::string& url,
                                 const std::string& fileName) {
    // TODO(crbug.com/751425): We should use the mock functionality
    // via |helper_|.
    url_test_helpers::RegisterMockedURLLoad(
        ToKURL(url),
        blink::test::CoreTestDataPath(WebString::FromUTF8(fileName)));
  }

  WebViewImpl* WebView() const { return helper_.GetWebView(); }
  LocalFrame* GetFrame() const { return helper_.LocalMainFrame()->GetFrame(); }

  static void ConfigureSettings(WebSettings* settings) {
    settings->SetJavaScriptEnabled(true);
    settings->SetLCDTextPreference(LCDTextPreference::kIgnored);
  }

  static void ConfigureAndroidSettings(WebSettings* settings) {
    ConfigureSettings(settings);
    frame_test_helpers::WebViewHelper::UpdateAndroidCompositingSettings(
        settings);
  }

  const DisplayItemClient& ScrollingBackgroundClient(const Document* document) {
    return document->GetLayoutView()
        ->GetScrollableArea()
        ->GetScrollingBackgroundDisplayItemClient();
  }

 protected:
  test::TaskEnvironment task_environment_;
  std::string base_url_;
  frame_test_helpers::WebViewHelper helper_;
};

INSTANTIATE_PAINT_TEST_SUITE_P(VisualViewportTest);

// Test that resizing the VisualViewport works as expected and that resizing the
// WebView resizes the VisualViewport.
TEST_P(VisualViewportTest, TestResize) {
  InitializeWithDesktopSettings();
  WebView()->MainFrameViewWidget()->Resize(gfx::Size(320, 240));
  WebView()->ResizeWithBrowserControls(
      gfx::Size(320, 240), gfx::Size(320, 240),
      WebView()->GetBrowserControls().Params());
  UpdateAllLifecyclePhases();

  NavigateTo("about:blank");
  ForceFullCompositingUpdate();

  VisualViewport& visual_viewport = GetFrame()->GetPage()->GetVisualViewport();

  gfx::Size web_view_size = WebView()->MainFrameViewWidget()->Size();

  // Make sure the visual viewport was initialized.
  EXPECT_EQ(web_view_size, visual_viewport.Size());

  // Resizing the WebView should change the VisualViewport.
  web_view_size = gfx::Size(640, 480);
  WebView()->MainFrameViewWidget()->Resize(web_view_size);
  WebView()->ResizeWithBrowserControls(
      web_view_size, web_view_size, WebView()->GetBrowserControls().Params());
  UpdateAllLifecyclePhases();
  EXPECT_EQ(web_view_size, WebView()->MainFrameViewWidget()->Size());
  EXPECT_EQ(web_view_size, visual_viewport.Size());

  // Resizing the visual viewport shouldn't affect the WebView.
  gfx::Size new_viewport_size = gfx::Size(320, 200);
  visual_viewport.SetSize(new_viewport_size);
  EXPECT_EQ(web_view_size, WebView()->MainFrameViewWidget()->Size());
  EXPECT_EQ(new_viewport_size, visual_viewport.Size());
}

// Make sure that the visibleContentRect method acurately reflects the scale and
// scroll location of the viewport with and without scrollbars.
TEST_P(VisualViewportTest, TestVisibleContentRect) {
  USE_NON_OVERLAY_SCROLLBARS_OR_QUIT();
  InitializeWithDesktopSettings();

  RegisterMockedHttpURLLoad("200-by-300.html");
  NavigateTo(base_url_ + "200-by-300.html");

  gfx::Size size(150, 100);
  // Vertical scrollbar width and horizontal scrollbar height.
  gfx::Size scrollbar_size(15, 15);

  WebView()->ResizeWithBrowserControls(
      size, size, WebView()->GetBrowserControls().Params());
  UpdateAllLifecyclePhases();

  // Scroll layout viewport and verify visibleContentRect.
  WebView()->MainFrameImpl()->SetScrollOffset(gfx::PointF(0, 50));

  VisualViewport& visual_viewport = GetFrame()->GetPage()->GetVisualViewport();
  EXPECT_EQ(gfx::Rect(gfx::Point(0, 0), size - scrollbar_size),
            visual_viewport.VisibleContentRect(kExcludeScrollbars));
  EXPECT_EQ(gfx::Rect(gfx::Point(0, 0), size),
            visual_viewport.VisibleContentRect(kIncludeScrollbars));

  WebView()->SetPageScaleFactor(2.0);

  // Scroll visual viewport and verify visibleContentRect.
  size = gfx::ScaleToFlooredSize(size, 0.5);
  scrollbar_size = gfx::ScaleToFlooredSize(scrollbar_size, 0.5);
  visual_viewport.SetLocation(gfx::PointF(10, 10));
  EXPECT_EQ(gfx::Rect(gfx::Point(10, 10), size - scrollbar_size),
            visual_viewport.VisibleContentRect(kExcludeScrollbars));
  EXPECT_EQ(gfx::Rect(gfx::Point(10, 10), size),
            visual_viewport.VisibleContentRect(kIncludeScrollbars));
}

// This tests that shrinking the WebView while the page is fully scrolled
// doesn't move the viewport up/left, it should keep the visible viewport
// unchanged from the user's perspective (shrinking the LocalFrameView will
// clamp the VisualViewport so we need to counter scroll the LocalFrameView to
// make it appear to stay still). This caused bugs like crbug.com/453859.
TEST_P(VisualViewportTest, TestResizeAtFullyScrolledPreservesViewportLocation) {
  InitializeWithDesktopSettings();
  WebView()->ResizeWithBrowserControls(
      gfx::Size(800, 600), gfx::Size(800, 600),
      WebView()->GetBrowserControls().Params());
  UpdateAllLifecyclePhases();

  RegisterMockedHttpURLLoad("content-width-1000.html");
  NavigateTo(base_url_ + "content-width-1000.html");

  LocalFrameView& frame_view = *WebView()->MainFrameImpl()->GetFrameView();
  VisualViewport& visual_viewport = GetFrame()->GetPage()->GetVisualViewport();

  visual_viewport.SetScale(2);

  // Fully scroll both viewports.
  frame_view.LayoutViewport()->SetScrollOffset(
      ScrollOffset(10000, 10000), mojom::blink::ScrollType::kProgrammatic);
  visual_viewport.Move(gfx::Vector2dF(10000, 10000));

  // Sanity check.
  ASSERT_EQ(ScrollOffset(400, 300), visual_viewport.GetScrollOffset());
  ASSERT_EQ(ScrollOffset(200, 1400),
            frame_view.LayoutViewport()->GetScrollOffset());

  gfx::Point expected_location =
      frame_view.GetScrollableArea()->VisibleContentRect().origin();

  // Shrink the WebView, this should cause both viewports to shrink and
  // WebView should do whatever it needs to do to preserve the visible
  // location.
  WebView()->ResizeWithBrowserControls(
      gfx::Size(700, 550), gfx::Size(800, 600),
      WebView()->GetBrowserControls().Params());
  UpdateAllLifecyclePhases();

  EXPECT_EQ(expected_location,
            frame_view.GetScrollableArea()->VisibleContentRect().origin());

  WebView()->ResizeWithBrowserControls(
      gfx::Size(800, 600), gfx::Size(800, 600),
      WebView()->GetBrowserControls().Params());
  UpdateAllLifecyclePhases();

  EXPECT_EQ(expected_location,
            frame_view.GetScrollableArea()->VisibleContentRect().origin());
}

// Test that the VisualViewport works as expected in case of a scaled
// and scrolled viewport - scroll down.
TEST_P(VisualViewportTest, TestResizeAfterVerticalScroll) {
  /*
                 200                                 200
        |                   |               |                   |
        |                   |               |                   |
        |                   | 800           |                   | 800
        |-------------------|               |                   |
        |                   |               |                   |
        |                   |               |                   |
        |                   |               |                   |
        |                   |   -------->   |                   |
        | 300               |               |                   |
        |                   |               |                   |
        |               400 |               |                   |
        |                   |               |-------------------|
        |                   |               |      75           |
        | 50                |               | 50             100|
        o-----              |               o----               |
        |    |              |               |   |  25           |
        |    |100           |               |-------------------|
        |    |              |               |                   |
        |    |              |               |                   |
        --------------------                --------------------

     */
  InitializeWithAndroidSettings();

  RegisterMockedHttpURLLoad("200-by-800-viewport.html");
  NavigateTo(base_url_ + "200-by-800-viewport.html");

  WebView()->MainFrameViewWidget()->Resize(gfx::Size(100, 200));

  // Scroll main frame to the bottom of the document
  WebView()->MainFrameImpl()->SetScrollOffset(gfx::PointF(0, 400));
  EXPECT_EQ(ScrollOffset(0, 400),
            GetFrame()->View()->LayoutViewport()->GetScrollOffset());

  WebView()->SetPageScaleFactor(2.0);

  // Scroll visual viewport to the bottom of the main frame
  VisualViewport& visual_viewport = GetFrame()->GetPage()->GetVisualViewport();
  visual_viewport.SetLocation(gfx::PointF(0, 300));
  EXPECT_VECTOR2DF_EQ(ScrollOffset(0, 300), visual_viewport.GetScrollOffset());

  // Verify the initial size of the visual viewport in the CSS pixels
  EXPECT_SIZEF_EQ(gfx::SizeF(50, 100), visual_viewport.VisibleRect().size());

  // Verify the paint property nodes and GeometryMapper cache.
  {
    UpdateAllLifecyclePhases();
    EXPECT_EQ(gfx::Transform::MakeScale(2),
              visual_viewport.GetPageScaleNode()->Matrix());
    EXPECT_EQ(gfx::Vector2dF(0, -300),
              visual_viewport.GetScrollTranslationNode()->Get2dTranslation());
    auto expected_projection = gfx::Transform::MakeScale(2);
    expected_projection.Translate(0, -300);
    EXPECT_EQ(expected_projection,
              GeometryMapper::SourceToDestinationProjection(
                  *visual_viewport.GetScrollTranslationNode(),
                  TransformPaintPropertyNode::Root()));
  }

  // Perform the resizing
  WebView()->MainFrameViewWidget()->Resize(gfx::Size(200, 100));

  // After resizing the scale changes 2.0 -> 4.0
  EXPECT_SIZEF_EQ(gfx::SizeF(50, 25), visual_viewport.VisibleRect().size());

  EXPECT_EQ(ScrollOffset(0, 625),
            GetFrame()->View()->LayoutViewport()->GetScrollOffset());
  EXPECT_VECTOR2DF_EQ(ScrollOffset(0, 75), visual_viewport.GetScrollOffset());

  // Verify the paint property nodes and GeometryMapper cache.
  {
    UpdateAllLifecyclePhases();
    EXPECT_EQ(gfx::Transform::MakeScale(4),
              visual_viewport.GetPageScaleNode()->Matrix());
    EXPECT_EQ(gfx::Vector2dF(0, -75),
              visual_viewport.GetScrollTranslationNode()->Get2dTranslation());
    auto expected_projection = gfx::Transform::MakeScale(4);
    expected_projection.Translate(0, -75);
    EXPECT_EQ(expected_projection,
              GeometryMapper::SourceToDestinationProjection(
                  *visual_viewport.GetScrollTranslationNode(),
                  TransformPaintPropertyNode::Root()));
  }
}

// Test that the VisualViewport works as expected in case if a scaled
// and scrolled viewport - scroll right.
TEST_P(VisualViewportTest, TestResizeAfterHorizontalScroll) {
  /*
                 200                                 200
        ---------------o-----               ---------------o-----
        |              |    |               |            25|    |
        |              |    |               |              -----|
        |           100|    |               |100             50 |
        |              |    |               |                   |
        |              ---- |               |-------------------|
        |                   |               |                   |
        |                   |               |                   |
        |                   |               |                   |
        |                   |               |                   |
        |                   |               |                   |
        |400                |   --------->  |                   |
        |                   |               |                   |
        |                   |               |                   |
        |                   |               |                   |
        |                   |               |                   |
        |                   |               |                   |
        |                   |               |                   |
        |                   |               |                   |
        |                   |               |                   |
        |-------------------|               |                   |
        |                   |               |                   |

     */
  InitializeWithAndroidSettings();

  RegisterMockedHttpURLLoad("200-by-800-viewport.html");
  NavigateTo(base_url_ + "200-by-800-viewport.html");

  WebView()->MainFrameViewWidget()->Resize(gfx::Size(100, 200));

  // Outer viewport takes the whole width of the document.

  WebView()->SetPageScaleFactor(2.0);

  // Scroll visual viewport to the right edge of the frame
  VisualViewport& visual_viewport = GetFrame()->GetPage()->GetVisualViewport();
  visual_viewport.SetLocation(gfx::PointF(150, 0));
  EXPECT_VECTOR2DF_EQ(ScrollOffset(150, 0), visual_viewport.GetScrollOffset());

  // Verify the initial size of the visual viewport in the CSS pixels
  EXPECT_SIZEF_EQ(gfx::SizeF(50, 100), visual_viewport.VisibleRect().size());

  // Verify the paint property nodes and GeometryMapper cache.
  {
    UpdateAllLifecyclePhases();
    EXPECT_EQ(gfx::Transform::MakeScale(2),
              visual_viewport.GetPageScaleNode()->Matrix());
    EXPECT_EQ(gfx::Vector2dF(-150, 0),
              visual_viewport.GetScrollTranslationNode()->Get2dTranslation());
    auto expected_projection = gfx::Transform::MakeScale(2);
    expected_projection.Translate(-150, 0);
    EXPECT_EQ(expected_projection,
              GeometryMapper::SourceToDestinationProjection(
                  *visual_viewport.GetScrollTranslationNode(),
                  TransformPaintPropertyNode::Root()));
  }

  WebView()->MainFrameViewWidget()->Resize(gfx::Size(200, 100));

  // After resizing the scale changes 2.0 -> 4.0
  EXPECT_SIZEF_EQ(gfx::SizeF(50, 25), visual_viewport.VisibleRect().size());

  EXPECT_EQ(ScrollOffset(0, 0),
            GetFrame()->View()->LayoutViewport()->GetScrollOffset());
  EXPECT_VECTOR2DF_EQ(ScrollOffset(150, 0), visual_viewport.GetScrollOffset());

  // Verify the paint property nodes and GeometryMapper cache.
  {
    UpdateAllLifecyclePhases();
    EXPECT_EQ(gfx::Transform::MakeScale(4),
              visual_viewport.GetPageScaleNode()->Matrix());
    EXPECT_EQ(gfx::Vector2dF(-150, 0),
              visual_viewport.GetScrollTranslationNode()->Get2dTranslation());
    auto expected_projection = gfx::Transform::MakeScale(4);
    expected_projection.Translate(-150, 0);
    EXPECT_EQ(expected_projection,
              GeometryMapper::SourceToDestinationProjection(
                  *visual_viewport.GetScrollTranslationNode(),
                  TransformPaintPropertyNode::Root()));
  }
}

// Make sure that the visibleRect method acurately reflects the scale and scroll
// location of the viewport.
TEST_P(VisualViewportTest, TestVisibleRect) {
  InitializeWithDesktopSettings();
  WebView()->MainFrameViewWidget()->Resize(gfx::Size(320, 240));

  NavigateTo("about:blank");
  ForceFullCompositingUpdate();

  VisualViewport& visual_viewport = GetFrame()->GetPage()->GetVisualViewport();

  // Initial visible rect should be the whole frame.
  EXPECT_EQ(WebView()->MainFrameViewWidget()->Size(), visual_viewport.Size());

  // Viewport is whole frame.
  gfx::Size size = gfx::Size(400, 200);
  WebView()->MainFrameViewWidget()->Resize(size);
  UpdateAllLifecyclePhases();
  visual_viewport.SetSize(size);

  // Scale the viewport to 2X; size should not change.
  gfx::RectF expected_rect((gfx::SizeF(size)));
  expected_rect.Scale(0.5);
  visual_viewport.SetScale(2);
  EXPECT_EQ(2, visual_viewport.Scale());
  EXPECT_EQ(size, visual_viewport.Size());
  EXPECT_RECTF_EQ(expected_rect, visual_viewport.VisibleRect());

  // Move the viewport.
  expected_rect.set_origin(gfx::PointF(5, 7));
  visual_viewport.SetLocation(expected_rect.origin());
  EXPECT_RECTF_EQ(expected_rect, visual_viewport.VisibleRect());

  expected_rect.set_origin(gfx::PointF(200, 100));
  visual_viewport.SetLocation(expected_rect.origin());
  EXPECT_RECTF_EQ(expected_rect, visual_viewport.VisibleRect());

  // Scale the viewport to 3X to introduce some non-int values.
  gfx::PointF oldLocation = expected_rect.origin();
  expected_rect = gfx::RectF(gfx::SizeF(size));
  expected_rect.Scale(1 / 3.0f);
  expected_rect.set_origin(oldLocation);
  visual_viewport.SetScale(3);
  EXPECT_RECTF_EQ(expected_rect, visual_viewport.VisibleRect());

  expected_rect.set_origin(gfx::PointF(0.25f, 0.333f));
  visual_viewport.SetLocation(expected_rect.origin());
  EXPECT_RECTF_EQ(expected_rect, visual_viewport.VisibleRect());
}

TEST_P(VisualViewportTest, TestFractionalScrollOffsetIsNotOverwritten) {
  ScopedFractionalScrollOffsetsForTest fractional_scroll_offsets(true);
  InitializeWithAndroidSettings();
  WebView()->MainFrameViewWidget()->Resize(gfx::Size(200, 250));

  RegisterMockedHttpURLLoad("200-by-800-viewport.html");
  NavigateTo(base_url_ + "200-by-800-viewport.html");

  LocalFrameView& frame_view = *WebView()->MainFrameImpl()->GetFrameView();
  frame_view.LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, 10.5), mojom::blink::ScrollType::kProgrammatic);
  frame_view.LayoutViewport()->ScrollableArea::SetScrollOffset(
      ScrollOffset(10, 30.5), mojom::blink::ScrollType::kCompositor);

  EXPECT_EQ(30.5, frame_view.LayoutViewport()->GetScrollOffset().y());
}

// Test that the viewport's scroll offset is always appropriately bounded such
// that the visual viewport always stays within the bounds of the main frame.
TEST_P(VisualViewportTest, TestOffsetClamping) {
  InitializeWithAndroidSettings();
  WebView()->MainFrameViewWidget()->Resize(gfx::Size(320, 240));

  WebURL base_url = url_test_helpers::ToKURL("http://example.com/");
  frame_test_helpers::LoadHTMLString(
      WebView()->MainFrameImpl(),
      "<!DOCTYPE html>"
      "<meta name='viewport' content='width=2000'>",
      base_url);
  ForceFullCompositingUpdate();

  // Visual viewport should be initialized to same size as frame so no scrolling
  // possible. At minimum scale, the viewport is 1280x960.
  VisualViewport& visual_viewport = GetFrame()->GetPage()->GetVisualViewport();
  ASSERT_EQ(0.25, visual_viewport.Scale());
  EXPECT_POINTF_EQ(gfx::PointF(0, 0), visual_viewport.VisibleRect().origin());

  visual_viewport.SetLocation(gfx::PointF(-1, -2));
  EXPECT_POINTF_EQ(gfx::PointF(0, 0), visual_viewport.VisibleRect().origin());

  visual_viewport.SetLocation(gfx::PointF(100, 200));
  EXPECT_POINTF_EQ(gfx::PointF(0, 0), visual_viewport.VisibleRect().origin());

  visual_viewport.SetLocation(gfx::PointF(-5, 10));
  EXPECT_POINTF_EQ(gfx::PointF(0, 0), visual_viewport.VisibleRect().origin());

  // Scale to 2x. The viewport's visible rect should now have a size of 160x120.
  visual_viewport.SetScale(2);
  gfx::PointF location(10, 50);
  visual_viewport.SetLocation(location);
  EXPECT_POINTF_EQ(location, visual_viewport.VisibleRect().origin());

  visual_viewport.SetLocation(gfx::PointF(10000, 10000));
  EXPECT_POINTF_EQ(gfx::PointF(1120, 840),
                   visual_viewport.VisibleRect().origin());

  visual_viewport.SetLocation(gfx::PointF(-2000, -2000));
  EXPECT_POINTF_EQ(gfx::PointF(0, 0), visual_viewport.VisibleRect().origin());

  // Make sure offset gets clamped on scale out. Scale to 1.25 so the viewport
  // is 256x192.
  visual_viewport.SetLocation(gfx::PointF(1120, 840));
  visual_viewport.SetScale(1.25);
  EXPECT_POINTF_EQ(gfx::PointF(1024, 768),
                   visual_viewport.VisibleRect().origin());

  // Scale out smaller than 1.
  visual_viewport.SetScale(0.25);
  EXPECT_POINTF_EQ(gfx::PointF(0, 0), visual_viewport.VisibleRect().origin());
}

// Test that the viewport can be scrolled around only within the main frame in
// the presence of viewport resizes, as would be the case if the on screen
// keyboard came up.
TEST_P(VisualViewportTest, TestOffsetClampingWithResize) {
  InitializeWithDesktopSettings();
  WebView()->MainFrameViewWidget()->Resize(gfx::Size(320, 240));

  NavigateTo("about:blank");
  ForceFullCompositingUpdate();

  // Visual viewport should be initialized to same size as frame so no scrolling
  // possible.
  VisualViewport& visual_viewport = GetFrame()->GetPage()->GetVisualViewport();
  EXPECT_POINTF_EQ(gfx::PointF(0, 0), visual_viewport.VisibleRect().origin());

  // Shrink the viewport vertically. The resize shouldn't affect the location,
  // but it should allow vertical scrolling.
  visual_viewport.SetSize(gfx::Size(320, 200));
  EXPECT_POINTF_EQ(gfx::PointF(0, 0), visual_viewport.VisibleRect().origin());
  visual_viewport.SetLocation(gfx::PointF(10, 20));
  EXPECT_POINTF_EQ(gfx::PointF(0, 20), visual_viewport.VisibleRect().origin());
  visual_viewport.SetLocation(gfx::PointF(0, 100));
  EXPECT_POINTF_EQ(gfx::PointF(0, 40), visual_viewport.VisibleRect().origin());
  visual_viewport.SetLocation(gfx::PointF(0, 10));
  EXPECT_POINTF_EQ(gfx::PointF(0, 10), visual_viewport.VisibleRect().origin());
  visual_viewport.SetLocation(gfx::PointF(0, -100));
  EXPECT_POINTF_EQ(gfx::PointF(0, 0), visual_viewport.VisibleRect().origin());

  // Repeat the above but for horizontal dimension.
  visual_viewport.SetSize(gfx::Size(280, 240));
  EXPECT_POINTF_EQ(gfx::PointF(0, 0), visual_viewport.VisibleRect().origin());
  visual_viewport.SetLocation(gfx::PointF(10, 20));
  EXPECT_POINTF_EQ(gfx::PointF(10, 0), visual_viewport.VisibleRect().origin());
  visual_viewport.SetLocation(gfx::PointF(100, 0));
  EXPECT_POINTF_EQ(gfx::PointF(40, 0), visual_viewport.VisibleRect().origin());
  visual_viewport.SetLocation(gfx::PointF(10, 0));
  EXPECT_POINTF_EQ(gfx::PointF(10, 0), visual_viewport.VisibleRect().origin());
  visual_viewport.SetLocation(gfx::PointF(-100, 0));
  EXPECT_POINTF_EQ(gfx::PointF(0, 0), visual_viewport.VisibleRect().origin());

  // Now with both dimensions.
  visual_viewport.SetSize(gfx::Size(280, 200));
  EXPECT_POINTF_EQ(gfx::PointF(0, 0), visual_viewport.VisibleRect().origin());
  visual_viewport.SetLocation(gfx::PointF(10, 20));
  EXPECT_POINTF_EQ(gfx::PointF(10, 20), visual_viewport.VisibleRect().origin());
  visual_viewport.SetLocation(gfx::PointF(100, 100));
  EXPECT_POINTF_EQ(gfx::PointF(40, 40), visual_viewport.VisibleRect().origin());
  visual_viewport.SetLocation(gfx::PointF(10, 3));
  EXPECT_POINTF_EQ(gfx::PointF(10, 3), visual_viewport.VisibleRect().origin());
  visual_viewport.SetLocation(gfx::PointF(-10, -4));
  EXPECT_POINTF_EQ(gfx::PointF(0, 0), visual_viewport.VisibleRect().origin());
}

// Test that the viewport is scrollable but bounded appropriately within the
// main frame when we apply both scaling and resizes.
TEST_P(VisualViewportTest, TestOffsetClampingWithResizeAndScale) {
  InitializeWithDesktopSettings();
  WebView()->MainFrameViewWidget()->Resize(gfx::Size(320, 240));

  NavigateTo("about:blank");
  ForceFullCompositingUpdate();

  // Visual viewport should be initialized to same size as WebView so no
  // scrolling possible.
  VisualViewport& visual_viewport = GetFrame()->GetPage()->GetVisualViewport();
  EXPECT_POINTF_EQ(gfx::PointF(0, 0), visual_viewport.VisibleRect().origin());

  // Zoom in to 2X so we can scroll the viewport to 160x120.
  visual_viewport.SetScale(2);
  visual_viewport.SetLocation(gfx::PointF(200, 200));
  EXPECT_POINTF_EQ(gfx::PointF(160, 120),
                   visual_viewport.VisibleRect().origin());

  // Now resize the viewport to make it 10px smaller. Since we're zoomed in by
  // 2X it should allow us to scroll by 5px more.
  visual_viewport.SetSize(gfx::Size(310, 230));
  visual_viewport.SetLocation(gfx::PointF(200, 200));
  EXPECT_POINTF_EQ(gfx::PointF(165, 125),
                   visual_viewport.VisibleRect().origin());

  // The viewport can be larger than the main frame (currently 320, 240) though
  // typically the scale will be clamped to prevent it from actually being
  // larger.
  visual_viewport.SetSize(gfx::Size(330, 250));
  EXPECT_EQ(gfx::Size(330, 250), visual_viewport.Size());

  // Resize both the viewport and the frame to be larger.
  WebView()->MainFrameViewWidget()->Resize(gfx::Size(640, 480));
  UpdateAllLifecyclePhases();
  EXPECT_EQ(WebView()->MainFrameViewWidget()->Size(), visual_viewport.Size());
  EXPECT_EQ(WebView()->MainFrameViewWidget()->Size(),
            GetFrame()->View()->FrameRect().size());
  visual_viewport.SetLocation(gfx::PointF(1000, 1000));
  EXPECT_POINTF_EQ(gfx::PointF(320, 240),
                   visual_viewport.VisibleRect().origin());

  // Make sure resizing the viewport doesn't change its offset if the resize
  // doesn't make the viewport go out of bounds.
  visual_viewport.SetLocation(gfx::PointF(200, 200));
  visual_viewport.SetSize(gfx::Size(880, 560));
  EXPECT_POINTF_EQ(gfx::PointF(200, 200),
                   visual_viewport.VisibleRect().origin());
}

// The main LocalFrameView's size should be set such that its the size of the
// visual viewport at minimum scale. If there's no explicit minimum scale set,
// the LocalFrameView should be set to the content width and height derived by
// the aspect ratio.
TEST_P(VisualViewportTest, TestFrameViewSizedToContent) {
  InitializeWithAndroidSettings();
  WebView()->MainFrameViewWidget()->Resize(gfx::Size(320, 240));

  RegisterMockedHttpURLLoad("200-by-300-viewport.html");
  NavigateTo(base_url_ + "200-by-300-viewport.html");

  WebView()->MainFrameViewWidget()->Resize(gfx::Size(600, 800));
  UpdateAllLifecyclePhases();

  // Note: the size is ceiled and should match the behavior in CC's
  // LayerImpl::bounds().
  EXPECT_EQ(gfx::Size(200, 267),
            WebView()->MainFrameImpl()->GetFrameView()->FrameRect().size());
}

// The main LocalFrameView's size should be set such that its the size of the
// visual viewport at minimum scale. On Desktop, the minimum scale is set at 1
// so make sure the LocalFrameView is sized to the viewport.
TEST_P(VisualViewportTest, TestFrameViewSizedToMinimumScale) {
  InitializeWithDesktopSettings();
  WebView()->MainFrameViewWidget()->Resize(gfx::Size(320, 240));

  RegisterMockedHttpURLLoad("200-by-300.html");
  NavigateTo(base_url_ + "200-by-300.html");

  WebView()->MainFrameViewWidget()->Resize(gfx::Size(100, 160));
  UpdateAllLifecyclePhases();

  EXPECT_EQ(gfx::Size(100, 160),
            WebView()->MainFrameImpl()->GetFrameView()->FrameRect().size());
}

// Test that attaching a new frame view resets the size of the inner viewport
// scroll layer. crbug.com/423189.
TEST_P(VisualViewportTest, TestAttachingNewFrameSetsInnerScrollLayerSize) {
  InitializeW
```