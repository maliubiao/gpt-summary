Response:
My thinking process to answer the request goes like this:

1. **Understand the Core Request:** The request asks for a summary of the functionality of the provided C++ code snippet from `browser_controls_test.cc`. It also specifically requests connections to web technologies (HTML, CSS, JavaScript), examples of logical reasoning with inputs and outputs, common user/programming errors, and an overall functional summary for this first part.

2. **Initial Scan for Keywords and Structure:** I quickly scan the code for recognizable keywords and structural elements:
    * `#include`: Indicates dependencies and the core purpose. The inclusion of `browser_controls.h` is a strong indicator of the file's main subject.
    * `namespace blink`: Confirms it's part of the Blink rendering engine.
    * `TEST_F`, `TEST`:  Clearly identifies this as a unit testing file using Google Test.
    * Class names like `BrowserControlsTest`, `BrowserControlsSimTest`, `BrowserControlsViewportUnitTest`: Suggest different testing scenarios related to browser controls.
    * Function names like `Initialize`, `VerticalScroll`, `GenerateEvent`, `CompositeForTest`, `SetSafeAreaInsets`, `ResolveSafeAreaInsetsBottom`:  Hint at specific functionalities being tested.
    * Mocked HTTP loads (`RegisterMockedHttpURLLoad`): Indicates testing of interactions with loaded web pages.
    * Usage of `WebGestureEvent`, `WebInputEvent`: Suggests testing input handling related to scrolling and potentially other gestures.
    * References to `LayoutViewport`, `ScrollOffset`, `PageScaleFactor`: Point to interactions with the layout and visual aspects of the rendered page.

3. **Identify the Main Functionality:** The presence of `BrowserControlsTest` and related classes, along with functions manipulating browser controls state (like `ResizeWithBrowserControls`, `SetShownRatio`, and assertions on `ContentOffset` and `BottomShownRatio`), immediately tells me the core purpose is testing the behavior of browser controls within the Blink rendering engine. Specifically, how they interact with scrolling and other factors.

4. **Relate to Web Technologies:**  I consider how browser controls manifest in a web browser:
    * **HTML:** The tests load HTML files (e.g., "large-div.html," "overflow-scrolling.html"). The behavior of browser controls directly affects how the HTML content is displayed and interacted with (e.g., scrolling).
    * **CSS:**  The code mentions `CSSVariableData` and resolving CSS variables related to safe area insets (`safe-area-inset-bottom`). This directly connects to CSS's role in defining the visual presentation and layout. The tests verify how browser controls affect these CSS-defined properties.
    * **JavaScript:** While this specific snippet doesn't have explicit JavaScript interaction, the tests set `JavaScriptEnabled(true)`. Browser controls' behavior can indirectly affect JavaScript execution (e.g., changes in viewport size or scroll position might trigger JavaScript events).

5. **Logical Reasoning and Examples:** I look for test cases that illustrate logical interactions and try to formulate input/output examples. The scrolling tests are the most prominent:
    * **Assumption:** Browser controls are initially visible.
    * **Input:** A downward scroll gesture.
    * **Output:** The browser controls retract, and the content scrolls.
    * **Assumption:** Browser controls are hidden.
    * **Input:** An upward scroll gesture.
    * **Output:** The browser controls appear.
    * The safe area inset tests provide another example:
        * **Assumption:** Dynamic safe area insets are enabled.
        * **Input:** Scrolling down when bottom controls are present.
        * **Output:** The `safe-area-inset-bottom` CSS variable changes dynamically based on the visibility of the bottom controls.

6. **Identify Potential Errors:** I consider common mistakes users or developers might make that these tests could help catch:
    * **Incorrect scroll handling:**  A bug where scrolling doesn't correctly hide/show browser controls or where the content scrolls unexpectedly.
    * **Incorrect safe area calculations:**  A bug where the safe area insets are not updated correctly when browser controls are present, potentially causing content to be obscured or mispositioned.
    * **Page scale issues:** A bug where the browser controls' behavior is incorrectly affected by page zoom.

7. **Synthesize the Summary:** Finally, I combine the observations into a concise summary, hitting the key points: testing browser control behavior (visibility, interaction with scrolling), its relationship to HTML/CSS (safe area insets), examples of logical flows, and potential error scenarios. I make sure to explicitly state that this is a unit testing file.

8. **Review and Refine:** I reread my summary to ensure it's accurate, clear, and directly addresses the prompt's requirements for part 1. I check for any redundancy or missing information. For instance, I initially focused solely on scrolling, but then added the safe area inset aspect as it was a significant part of the code.
好的，让我们来分析一下 `blink/renderer/core/frame/browser_controls_test.cc` 这个文件的功能。

**功能归纳（针对提供的第一部分代码）：**

这个 C++ 文件是 Chromium Blink 引擎中用于测试 `blink::BrowserControls` 类功能的单元测试文件。它的主要目的是验证浏览器控制栏（通常指浏览器顶部地址栏和底部导航栏等）在各种场景下的行为，特别是与页面滚动交互时的行为。

**更具体的功能点包括：**

1. **测试浏览器控制栏的显示和隐藏：**  通过模拟用户滚动操作（向上或向下），测试浏览器控制栏是否能正确地显示或隐藏。
2. **测试浏览器控制栏偏移量的计算：** 验证在滚动过程中，浏览器控制栏的偏移量（`ContentOffset`）是否按照预期进行计算。
3. **测试浏览器控制栏与页面滚动的交互：**  确认当浏览器控制栏处于不同显示状态时，页面的滚动行为是否正确，例如，在隐藏浏览器控制栏后，页面的滚动量是否会相应增加。
4. **测试底部浏览器控制栏的显示和隐藏：** 专门测试底部浏览器控制栏（如果存在）在滚动时的行为，包括 `BottomShownRatio` 的计算。
5. **测试动态安全区域插边 (Dynamic Safe Area Insets) 的影响：**  验证在启用动态安全区域插边功能后，浏览器控制栏的显示和隐藏是否会影响到安全区域插边的计算，特别是底部插边 (`safe-area-inset-bottom`)。这涉及到 CSS 环境变量的解析。
6. **测试水平滚动对浏览器控制栏的影响：**  确认水平滚动操作不会影响浏览器控制栏的状态。
7. **测试页面缩放 (Page Scale) 对浏览器控制栏的影响：**  验证页面缩放操作不会干扰浏览器控制栏的滚动和显示逻辑。
8. **使用模拟事件进行测试：**  通过 `WebGestureEvent` 模拟用户的触摸滚动事件，以便精确地控制输入并验证结果。
9. **依赖于测试框架：** 使用 Google Test (`TEST_F`, `EXPECT_FLOAT_EQ`, `EXPECT_EQ`) 和 Google Mock (`gmock`) 来组织和断言测试结果。
10. **模拟环境：**  使用了 `SimTest` 和 `ScopedMockOverlayScrollbars` 等工具来创建模拟的浏览器环境，以便进行隔离测试。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **CSS:**
    * **功能关系：** 文件中测试了动态安全区域插边 (`DynamicSafeAreaInsetsForTest`)，这直接关联到 CSS 环境变量 `safe-area-inset-bottom`。浏览器控制栏的显示状态会影响这个 CSS 变量的值，从而影响页面的布局。
    * **举例说明：** 当底部浏览器控制栏显示时，`safe-area-inset-bottom` 的值可能会减小，以确保页面内容不会被控制栏遮挡。反之，当底部控制栏隐藏时，`safe-area-inset-bottom` 的值可能会恢复到其最大值。在测试中，`ResolveSafeAreaInsetsBottom()` 函数用于解析和验证这个 CSS 变量的值。例如，在 `DynamicSafeAreaInsetBottomUntilScrollDownFinished` 测试中，会断言在滚动过程中和滚动完成后 `safe-area-inset-bottom` 的值是否符合预期。

* **HTML:**
    * **功能关系：** 测试加载不同的 HTML 文件 (`large-div.html`, `overflow-scrolling.html` 等) 来模拟不同的页面结构和内容，验证浏览器控制栏在这些不同页面下的行为是否一致。页面的可滚动性、内容高度等因素会影响浏览器控制栏的显示和隐藏逻辑。
    * **举例说明：**  `Initialize("large-div.html")` 加载了一个内容高度超过视口高度的页面，使得页面可以滚动。测试会模拟滚动操作来观察浏览器控制栏的反应。

* **JavaScript:**
    * **功能关系：** 虽然这段代码本身不直接涉及 JavaScript 的执行，但浏览器控制栏的状态变化可能会触发 JavaScript 事件（例如，`resize` 或 `scroll` 事件）。测试确保了这些状态变化是正确发生的，这间接影响了 JavaScript 的行为。
    * **举例说明：**  如果 JavaScript 代码监听了 `resize` 事件，当浏览器控制栏显示或隐藏导致视口大小改变时，应该触发该事件。这个测试文件确保了浏览器控制栏的这些状态变化是准确的，从而保证了 `resize` 事件触发的正确性。

**逻辑推理与假设输入输出：**

* **假设输入：**  用户在浏览器控制栏可见的情况下，执行一个向下的滚动手势，滚动距离为 30 像素。假设浏览器控制栏的高度为 50 像素。
* **预期输出：**
    * 浏览器控制栏的 `ContentOffset` 将会减少，变为 50 - 30 = 20 像素。
    * 页面的滚动偏移量不会立即改变，因为前 50 像素的向下滚动会被浏览器控制栏“吸收”。
    * 可以通过 `EXPECT_FLOAT_EQ(20.f, web_view->GetBrowserControls().ContentOffset());` 和 `EXPECT_EQ(ScrollOffset(0, 0), GetFrame()->View()->LayoutViewport()->GetScrollOffset());` 来验证。

* **假设输入：** 用户在浏览器控制栏完全隐藏的情况下，执行一个向上的滚动手势，滚动距离为 20 像素。假设浏览器控制栏的高度为 50 像素。
* **预期输出：**
    * 浏览器控制栏的 `ContentOffset` 将会增加，变为 0 + 20 = 20 像素。
    * 页面的滚动偏移量保持不变。
    * 可以通过 `EXPECT_FLOAT_EQ(20.f, web_view->GetBrowserControls().ContentOffset());` 和 `EXPECT_EQ(ScrollOffset(0, 0), GetFrame()->View()->LayoutViewport()->GetScrollOffset());` 来验证。

**用户或编程常见的使用错误举例：**

* **错误假设滚动量总是直接影响页面：** 开发者可能会错误地认为每次滚动操作都会直接导致页面滚动。但实际上，在浏览器控制栏可见时，一部分滚动量会被用于控制栏的显示和隐藏，而不是直接滚动页面。这个测试文件帮助验证了这种情况下页面的滚动行为是否符合预期。
* **忽略浏览器控制栏对视口大小的影响：**  在进行布局计算或处理 JavaScript 事件时，开发者可能没有考虑到浏览器控制栏的存在以及它对视口大小的影响。例如，固定定位的元素可能会因为浏览器控制栏的显示而出现遮挡。动态安全区域插边的测试就旨在解决这类问题，确保内容不会被控制栏覆盖。
* **错误地假设安全区域插边是静态的：** 开发者可能认为安全区域插边是固定不变的，但实际上，在某些情况下（例如，存在可隐藏的浏览器控制栏），安全区域插边是动态变化的。未能正确处理这种动态变化可能导致布局问题。

**总结一下这个第一部分代码的功能：**

这部分代码主要定义了一个名为 `BrowserControlsTest` 的 C++ 类，它继承自 `testing::Test`，用于对 `blink::BrowserControls` 类进行详细的单元测试。这些测试涵盖了浏览器控制栏在各种滚动场景下的显示、隐藏、偏移量计算以及与页面滚动的交互。此外，它还测试了动态安全区域插边功能对浏览器控制栏行为的影响，以及水平滚动和页面缩放对控制栏的影响。这个测试文件使用了模拟的滚动事件和浏览器环境，并通过断言来验证浏览器控制栏的行为是否符合预期。 它是确保 Blink 引擎中浏览器控制栏功能正确性的重要组成部分。

Prompt: 
```
这是目录为blink/renderer/core/frame/browser_controls_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2015 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "third_party/blink/renderer/core/frame/browser_controls.h"

#include "build/build_config.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/input/web_coalesced_input_event.h"
#include "third_party/blink/public/web/web_element.h"
#include "third_party/blink/public/web/web_settings.h"
#include "third_party/blink/renderer/core/css/css_variable_data.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/qualified_name.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/fullscreen/fullscreen.h"
#include "third_party/blink/renderer/core/geometry/dom_rect.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/paint/paint_and_raster_invalidation_test.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/testing/scoped_mock_overlay_scrollbars.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/url_loader_mock_factory.h"
#include "third_party/blink/renderer/platform/testing/url_test_helpers.h"
#include "ui/gfx/geometry/insets.h"

namespace blink {

namespace {

// From browser_controls_offset_manager.cc.
const int64_t kShowHideMaxDurationMs = 200;

}  // namespace

// These tests cover interactions between scrolling and browser controls, with a
// focus on Blink-observable side effects. Scrolling happens in the compositor,
// but browser controls state is propagated into blink::BrowserControls through
// LayerTreeHost::ApplyCompositorChanges. Additional tests relating to cc state
// can be found under LayerTreeHostImplBrowserControlsTest.
class BrowserControlsTest : public testing::Test,
                            public ScopedMockOverlayScrollbars {
 public:
  BrowserControlsTest() : base_url_("http://www.test.com/") {
    RegisterMockedHttpURLLoad("large-div.html");
    RegisterMockedHttpURLLoad("overflow-scrolling.html");
    RegisterMockedHttpURLLoad("iframe-scrolling.html");
    RegisterMockedHttpURLLoad("iframe-scrolling-inner.html");
    RegisterMockedHttpURLLoad("percent-height.html");
    RegisterMockedHttpURLLoad("v-size.html");
    RegisterMockedHttpURLLoad("sv-size.html");
    RegisterMockedHttpURLLoad("lv-size.html");
    RegisterMockedHttpURLLoad("dv-size.html");
    RegisterMockedHttpURLLoad("vh-height-width-800.html");
    RegisterMockedHttpURLLoad("95-vh.html");
    RegisterMockedHttpURLLoad("vh-height-width-800-extra-wide.html");
    RegisterMockedHttpURLLoad("fullscreen_iframe.html");
    RegisterMockedHttpURLLoad("fullscreen_div.html");
  }

  ~BrowserControlsTest() override {
    URLLoaderMockFactory::GetSingletonInstance()
        ->UnregisterAllURLsAndClearMemoryCache();
  }

  WebViewImpl* Initialize(const std::string& page_name = "large-div.html") {
    // Load a page with large body and set viewport size to 400x400 to ensure
    // main frame is scrollable.
    helper_.InitializeAndLoad(base_url_ + page_name, nullptr, nullptr,
                              &ConfigureSettings);

    helper_.Resize(gfx::Size(400, 400));
    return GetWebView();
  }

  static void ConfigureSettings(WebSettings* settings) {
    settings->SetJavaScriptEnabled(true);
    frame_test_helpers::WebViewHelper::UpdateAndroidCompositingSettings(
        settings);
  }

  void RegisterMockedHttpURLLoad(const std::string& file_name) {
    url_test_helpers::RegisterMockedURLLoadFromBase(
        WebString::FromUTF8(base_url_), test::CoreTestDataPath(),
        WebString::FromUTF8(file_name));
  }

  WebGestureEvent GenerateEvent(WebInputEvent::Type type,
                                int delta_x = 0,
                                int delta_y = 0) {
    WebGestureEvent event(type, WebInputEvent::kNoModifiers,
                          WebInputEvent::GetStaticTimeStampForTests(),
                          WebGestureDevice::kTouchscreen);
    event.SetPositionInWidget(gfx::PointF(100, 100));
    if (type == WebInputEvent::Type::kGestureScrollUpdate) {
      event.data.scroll_update.delta_x = delta_x;
      event.data.scroll_update.delta_y = delta_y;
    } else if (type == WebInputEvent::Type::kGestureScrollBegin) {
      event.data.scroll_begin.delta_x_hint = delta_x;
      event.data.scroll_begin.delta_y_hint = delta_y;
    }
    return event;
  }

  void VerticalScroll(float delta_y) {
    GetWebFrameWidget()->DispatchThroughCcInputHandler(
        GenerateEvent(WebInputEvent::Type::kGestureScrollBegin, 0, delta_y));
    GetWebFrameWidget()->DispatchThroughCcInputHandler(
        GenerateEvent(WebInputEvent::Type::kGestureScrollUpdate, 0, delta_y));
    GetWebFrameWidget()->DispatchThroughCcInputHandler(
        GenerateEvent(WebInputEvent::Type::kGestureScrollEnd));

    // Runs LayerTreeHost::ApplyCompositorChanges, which sends scroll deltas etc
    // back to Blink.
    CompositeForTest();
  }

  Element* GetElementById(const WebString& id) {
    return static_cast<Element*>(
        GetWebView()->MainFrameImpl()->GetDocument().GetElementById(id));
  }

  WebViewImpl* GetWebView() const { return helper_.GetWebView(); }
  LocalFrame* GetFrame() const { return helper_.LocalMainFrame()->GetFrame(); }
  VisualViewport& GetVisualViewport() const {
    return helper_.GetWebView()->GetPage()->GetVisualViewport();
  }
  frame_test_helpers::TestWebFrameWidget* GetWebFrameWidget() const {
    return helper_.GetMainFrameWidget();
  }

  void UpdateAllLifecyclePhases() {
    GetWebView()->MainFrameViewWidget()->UpdateAllLifecyclePhases(
        DocumentUpdateReason::kTest);
  }

  void CompositeForTest(base::TimeDelta animation_delay = base::TimeDelta()) {
    accumulated_animation_delay_ += animation_delay;
    helper_.GetLayerTreeHost()->CompositeForTest(
        base::TimeTicks::Now() + accumulated_animation_delay_, false,
        base::OnceClosure());
  }

  void FinishAnimation() {
    // First tick (through LTHI::Animate), to initialize
    // BrowserControlsOffsetManager::Animation::start_time_.
    CompositeForTest();

    // Second tick to set final value.
    CompositeForTest(base::Milliseconds(kShowHideMaxDurationMs));
  }

  void SetSafeAreaInsets(LocalFrame* frame, const gfx::Insets& insets) {
    GetWebView()->GetPage()->SetMaxSafeAreaInsets(frame, insets);
  }

  String ResolveSafeAreaInsetsBottom() {
    return ResolveSafeAreaInsetsBottom(GetFrame());
  }

  String ResolveSafeAreaInsetsBottom(LocalFrame* frame) {
    DocumentStyleEnvironmentVariables& vars =
        frame->GetDocument()->GetStyleEngine().EnsureEnvironmentVariables();

    CSSVariableData* data =
        vars.ResolveVariable(AtomicString("safe-area-inset-bottom"), {});
    EXPECT_NE(nullptr, data);
    return data->Serialize();
  }

 private:
  test::TaskEnvironment task_environment_;
  ScopedTestingPlatformSupport<TestingPlatformSupport> platform_;
  std::string base_url_;
  frame_test_helpers::WebViewHelper helper_;
  base::TimeDelta accumulated_animation_delay_;
};

class BrowserControlsSimTest : public SimTest {
 public:
  BrowserControlsSimTest() {}

  void SetUp() override {
    SimTest::SetUp();
    frame_test_helpers::WebViewHelper::UpdateAndroidCompositingSettings(
        WebView().GetSettings());
    WebView().SetDefaultPageScaleLimits(0.25f, 5);
    Compositor().LayerTreeHost()->UpdateBrowserControlsState(
        cc::BrowserControlsState::kBoth, cc::BrowserControlsState::kShown,
        false, std::nullopt);
    WebView().ResizeWithBrowserControls(gfx::Size(412, 604), 56.f, 50.f, true);
  }

  WebGestureEvent GenerateEvent(WebInputEvent::Type type,
                                int delta_x = 0,
                                int delta_y = 0) {
    WebGestureEvent event(type, WebInputEvent::kNoModifiers,
                          WebInputEvent::GetStaticTimeStampForTests(),
                          WebGestureDevice::kTouchscreen);
    event.SetPositionInWidget(gfx::PointF(100, 100));
    if (type == WebInputEvent::Type::kGestureScrollUpdate) {
      event.data.scroll_update.delta_x = delta_x;
      event.data.scroll_update.delta_y = delta_y;
    } else if (type == WebInputEvent::Type::kGestureScrollBegin) {
      event.data.scroll_begin.delta_x_hint = delta_x;
      event.data.scroll_begin.delta_y_hint = delta_y;
    }
    return event;
  }

  void VerticalScroll(float delta_y) {
    GetWebFrameWidget().DispatchThroughCcInputHandler(
        GenerateEvent(WebInputEvent::Type::kGestureScrollBegin, 0, delta_y));
    GetWebFrameWidget().DispatchThroughCcInputHandler(
        GenerateEvent(WebInputEvent::Type::kGestureScrollUpdate, 0, delta_y));
    GetWebFrameWidget().DispatchThroughCcInputHandler(
        GenerateEvent(WebInputEvent::Type::kGestureScrollEnd));

    // Runs LayerTreeHost::ApplyCompositorChanges, which sends scroll deltas etc
    // back to Blink.
    Compositor().BeginFrame();
  }
};

struct ViewportUnitTestCase {
  // The file to load in the WebView. See mocked files in BrowserControlsTest().
  const char* filename;
  // The width that 50*vw should resolve to.
  float width;
  // The height that 50*vh should resolve to.
  float height;
};

class BrowserControlsViewportUnitTest
    : public BrowserControlsTest,
      public ::testing::WithParamInterface<ViewportUnitTestCase> {};

// Disable these tests on Mac OSX until further investigation.
// Local build on Mac is OK but the bot fails. This is not an issue as
// Browser Controls are currently only used on Android.
#if BUILDFLAG(IS_MAC)
#define MAYBE(test) DISABLED_##test
#else
#define MAYBE(test) test
#endif

// Scrolling down should hide browser controls.
TEST_F(BrowserControlsTest, MAYBE(HideOnScrollDown)) {
  WebViewImpl* web_view = Initialize();
  // initialize browser controls to be shown.
  web_view->ResizeWithBrowserControls(web_view->MainFrameViewWidget()->Size(),
                                      50.f, 0, true);
  web_view->GetBrowserControls().SetShownRatio(1, 1);
  CompositeForTest();

  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollBegin));
  EXPECT_FLOAT_EQ(50.f, web_view->GetBrowserControls().ContentOffset());

  // Browser controls should be scrolled partially and page should not scroll.
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollUpdate, 0, -25.f));
  CompositeForTest();
  EXPECT_FLOAT_EQ(25.f, web_view->GetBrowserControls().ContentOffset());
  EXPECT_EQ(ScrollOffset(0, 0),
            GetFrame()->View()->LayoutViewport()->GetScrollOffset());

  // Browser controls should consume 25px and become hidden. Excess scroll
  // should be
  // consumed by the page.
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollUpdate, 0, -40.f));
  CompositeForTest();
  EXPECT_FLOAT_EQ(0.f, web_view->GetBrowserControls().ContentOffset());
  EXPECT_EQ(ScrollOffset(0, 15),
            GetFrame()->View()->LayoutViewport()->GetScrollOffset());

  // Only page should consume scroll
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollUpdate, 0, -20.f));
  CompositeForTest();
  EXPECT_FLOAT_EQ(0.f, web_view->GetBrowserControls().ContentOffset());
  EXPECT_EQ(ScrollOffset(0, 35),
            GetFrame()->View()->LayoutViewport()->GetScrollOffset());
}

// Scrolling down should hide bottom browser controls.
TEST_F(BrowserControlsTest, MAYBE(HideBottomControlsOnScrollDown)) {
  WebViewImpl* web_view = Initialize();
  // initialize browser controls to be shown.
  web_view->ResizeWithBrowserControls(web_view->MainFrameViewWidget()->Size(),
                                      0, 50.f, true);
  web_view->GetBrowserControls().SetShownRatio(0.0, 1);
  CompositeForTest();

  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollBegin));
  EXPECT_FLOAT_EQ(0.f, web_view->GetBrowserControls().ContentOffset());

  // Bottom controls and page content should both scroll and there should be
  // no content offset.
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollUpdate, 0, -25.f));
  CompositeForTest();
  EXPECT_FLOAT_EQ(0.f, web_view->GetBrowserControls().ContentOffset());
  EXPECT_FLOAT_EQ(0.5f, web_view->GetBrowserControls().BottomShownRatio());
  EXPECT_EQ(ScrollOffset(0, 25.f),
            GetFrame()->View()->LayoutViewport()->GetScrollOffset());

  // Browser controls should become completely hidden.
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollBegin));
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollUpdate, 0, -40.f));
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollEnd));
  CompositeForTest();
  EXPECT_FLOAT_EQ(0.f, web_view->GetBrowserControls().ContentOffset());
  EXPECT_FLOAT_EQ(0.f, web_view->GetBrowserControls().BottomShownRatio());
  EXPECT_EQ(ScrollOffset(0, 65.f),
            GetFrame()->View()->LayoutViewport()->GetScrollOffset());
}

TEST_F(BrowserControlsTest,
       MAYBE(DynamicSafeAreaInsetBottomUntilScrollDownFinished)) {
  ScopedDynamicSafeAreaInsetsForTest dynamic_safe_area_insets(true);
  ScopedDynamicSafeAreaInsetsOnScrollForTest on_scroll(false);

  WebViewImpl* web_view = Initialize();
  web_view->GetSettings()->SetDynamicSafeAreaInsetsEnabled(true);
  SetSafeAreaInsets(GetFrame(), gfx::Insets().set_bottom(30));

  // initialize browser controls to be shown.
  web_view->GetBrowserControls().SetShownRatio(0.0, 1);
  web_view->ResizeWithBrowserControls(web_view->MainFrameViewWidget()->Size(),
                                      0, 50.f, true);
  CompositeForTest();
  // Bottom insets should be 0, as browser control is presented and it's taller
  // than the bottom of the insets.
  EXPECT_EQ("0px", ResolveSafeAreaInsetsBottom());

  VerticalScroll(-40.0f);

  // The safe area does not update until the scroll is finished.
  EXPECT_FLOAT_EQ(0.2f, web_view->GetBrowserControls().BottomShownRatio());
  EXPECT_EQ("0px", ResolveSafeAreaInsetsBottom());

  // Simulate the scroll is finished, and call the browser control
  // to resize the page.
  FinishAnimation();
  web_view->ResizeWithBrowserControls(web_view->MainFrameViewWidget()->Size(),
                                      0, 50.f, false);
  UpdateAllLifecyclePhases();

  EXPECT_FLOAT_EQ(0.f, web_view->GetBrowserControls().BottomShownRatio());
  EXPECT_EQ("30px", ResolveSafeAreaInsetsBottom());
}

TEST_F(BrowserControlsTest, MAYBE(DynamicSafeAreaInsetBottomScrollDown)) {
  ScopedDynamicSafeAreaInsetsForTest dynamic_safe_area_insets(true);
  ScopedDynamicSafeAreaInsetsOnScrollForTest on_scroll(true);

  WebViewImpl* web_view = Initialize();
  web_view->GetSettings()->SetDynamicSafeAreaInsetsEnabled(true);
  SetSafeAreaInsets(GetFrame(), gfx::Insets().set_bottom(30));

  // initialize browser controls to be shown.
  web_view->ResizeWithBrowserControls(web_view->MainFrameViewWidget()->Size(),
                                      0, 50.f, true);
  web_view->GetBrowserControls().SetShownRatio(0.0, 1);
  CompositeForTest();
  // Bottom insets should be 0, as browser control is presented and it's taller
  // than the bottom of the insets.
  EXPECT_EQ("0px", ResolveSafeAreaInsetsBottom());

  // Bottom controls and page content should both scroll and there should be
  // no content offset.
  VerticalScroll(-40.0f);

  // Calculate the bottom safe area insets, as there's no min height for bottom
  // controls.
  // shown_ratio (0.2) = 1 - scroll_offset(40) / bottom_controls_height(50)
  // inset.bottom (20) = safe_area_insets.bottom(30) -
  //                     bottom_controls_height(50) * shown_ratio (0.2)
  EXPECT_FLOAT_EQ(0.2f, web_view->GetBrowserControls().BottomShownRatio());
  EXPECT_EQ("20px", ResolveSafeAreaInsetsBottom());

  // Browser controls should become completely hidden.
  VerticalScroll(-40.0f);

  EXPECT_FLOAT_EQ(0.f, web_view->GetBrowserControls().BottomShownRatio());
  EXPECT_EQ("30px", ResolveSafeAreaInsetsBottom());
}

// Scrolling up should show browser controls.
TEST_F(BrowserControlsTest, MAYBE(ShowOnScrollUp)) {
  WebViewImpl* web_view = Initialize();
  // initialize browser controls to be hidden.
  web_view->ResizeWithBrowserControls(web_view->MainFrameViewWidget()->Size(),
                                      50.f, 0, false);
  web_view->GetBrowserControls().SetShownRatio(0, 0);
  CompositeForTest();

  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollBegin));
  EXPECT_FLOAT_EQ(0.f, web_view->GetBrowserControls().ContentOffset());

  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollUpdate, 0, 10.f));
  CompositeForTest();
  EXPECT_FLOAT_EQ(10.f, web_view->GetBrowserControls().ContentOffset());
  EXPECT_EQ(ScrollOffset(0, 0),
            GetFrame()->View()->LayoutViewport()->GetScrollOffset());

  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollUpdate, 0, 50.f));
  CompositeForTest();
  EXPECT_FLOAT_EQ(50.f, web_view->GetBrowserControls().ContentOffset());
  EXPECT_EQ(ScrollOffset(0, 0),
            GetFrame()->View()->LayoutViewport()->GetScrollOffset());
}

// Scrolling up should show the bottom browser controls.
TEST_F(BrowserControlsTest, MAYBE(ShowBottomControlsOnScrollUp)) {
  WebViewImpl* web_view = Initialize();
  // initialize browser controls to be hidden.
  web_view->ResizeWithBrowserControls(web_view->MainFrameViewWidget()->Size(),
                                      0, 50.f, false);
  web_view->GetBrowserControls().SetShownRatio(0, 0);
  CompositeForTest();

  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollBegin));
  EXPECT_FLOAT_EQ(0.f, web_view->GetBrowserControls().ContentOffset());

  // Allow some space to scroll up.
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollBegin));
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollUpdate, 0, -50.f));
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollEnd));
  CompositeForTest();

  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollBegin));
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollUpdate, 0, 25.f));
  CompositeForTest();
  EXPECT_FLOAT_EQ(0.5f, web_view->GetBrowserControls().BottomShownRatio());

  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollEnd));
  FinishAnimation();
  EXPECT_FLOAT_EQ(0.f, web_view->GetBrowserControls().ContentOffset());
  EXPECT_FLOAT_EQ(1.f, web_view->GetBrowserControls().BottomShownRatio());
  EXPECT_EQ(ScrollOffset(0, 25),
            GetFrame()->View()->LayoutViewport()->GetScrollOffset());
}

TEST_F(BrowserControlsTest,
       MAYBE(DynamicSafeAreaInsetBottomUntilScrollUpFinished)) {
  ScopedDynamicSafeAreaInsetsForTest dynamic_safe_area_insets(true);
  ScopedDynamicSafeAreaInsetsOnScrollForTest on_scroll(false);

  WebViewImpl* web_view = Initialize();
  web_view->GetSettings()->SetDynamicSafeAreaInsetsEnabled(true);
  SetSafeAreaInsets(GetFrame(), gfx::Insets().set_bottom(30));

  // initialize browser controls to be shown.
  web_view->GetBrowserControls().SetShownRatio(0, 0);
  web_view->ResizeWithBrowserControls(web_view->MainFrameViewWidget()->Size(),
                                      0, 50.f, false);
  CompositeForTest();

  // Bottom insets should be 30, as browser control is fully hidden.
  EXPECT_EQ("30px", ResolveSafeAreaInsetsBottom());

  VerticalScroll(40.0f);

  // Safe area insets does not update when DynamicSafeAreaInsetsOnScroll
  // flag is disabled.
  EXPECT_FLOAT_EQ(0.8f, web_view->GetBrowserControls().BottomShownRatio());
  EXPECT_EQ("30px", ResolveSafeAreaInsetsBottom());

  // Simulate the scroll is finished, and call the browser control
  // to resize the page.
  FinishAnimation();
  web_view->ResizeWithBrowserControls(web_view->MainFrameViewWidget()->Size(),
                                      0, 50.f, true);
  UpdateAllLifecyclePhases();

  // Browser controls full shown when the entire scroll is finished.
  EXPECT_FLOAT_EQ(1.0f, web_view->GetBrowserControls().BottomShownRatio());
  EXPECT_EQ("0px", ResolveSafeAreaInsetsBottom());
}

TEST_F(BrowserControlsTest, MAYBE(DynamicSafeAreaInsetBottomScrollUp)) {
  ScopedDynamicSafeAreaInsetsForTest dynamic_safe_area_insets(true);
  ScopedDynamicSafeAreaInsetsOnScrollForTest on_scroll(true);

  WebViewImpl* web_view = Initialize();
  web_view->GetSettings()->SetDynamicSafeAreaInsetsEnabled(true);
  SetSafeAreaInsets(GetFrame(), gfx::Insets().set_bottom(30));

  // initialize browser controls to be shown.
  web_view->ResizeWithBrowserControls(web_view->MainFrameViewWidget()->Size(),
                                      0, 50.f, true);
  web_view->GetBrowserControls().SetShownRatio(0, 0);
  CompositeForTest();

  // Bottom insets should be 30, as browser control is fully hidden.
  EXPECT_EQ("30px", ResolveSafeAreaInsetsBottom());

  VerticalScroll(20.0f);

  // shown_ratio (0.4) = scroll_offset(20) / bottom_controls_height(50)
  // inset.bottom (0) = safe_area_insets.bottom(30) -
  //                     bottom_controls_height(50) * shown_ratio (0.4)
  EXPECT_FLOAT_EQ(0.4f, web_view->GetBrowserControls().BottomShownRatio());
  EXPECT_EQ("10px", ResolveSafeAreaInsetsBottom());

  VerticalScroll(20.0f);

  // Calculate the bottom safe area insets, as there's no min height for bottom
  // controls.
  // shown_ratio (0.8) = scroll_offset(40) / bottom_controls_height(50)
  // inset.bottom (0) = max(0, safe_area_insets.bottom(30) -
  //                     bottom_controls_height(50) * shown_ratio (0.8))
  EXPECT_FLOAT_EQ(0.8f, web_view->GetBrowserControls().BottomShownRatio());
  EXPECT_EQ("0px", ResolveSafeAreaInsetsBottom());
}

// Scrolling up after previous scroll downs should cause browser controls to be
// shown only after all previously scrolled down amount is compensated.
TEST_F(BrowserControlsTest, MAYBE(ScrollDownThenUp)) {
  WebViewImpl* web_view = Initialize();
  // initialize browser controls to be shown and position page at 100px.
  web_view->ResizeWithBrowserControls(web_view->MainFrameViewWidget()->Size(),
                                      50.f, 0, true);
  web_view->GetBrowserControls().SetShownRatio(1, 1);
  GetFrame()->View()->GetScrollableArea()->SetScrollOffset(
      ScrollOffset(0, 100), mojom::blink::ScrollType::kProgrammatic);
  CompositeForTest();

  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollBegin));
  EXPECT_FLOAT_EQ(50.f, web_view->GetBrowserControls().ContentOffset());

  // Scroll down to completely hide browser controls. Excess deltaY (100px)
  // should be consumed by the page.
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollUpdate, 0, -150.f));
  CompositeForTest();
  EXPECT_FLOAT_EQ(0.f, web_view->GetBrowserControls().ContentOffset());
  EXPECT_EQ(ScrollOffset(0, 200),
            GetFrame()->View()->LayoutViewport()->GetScrollOffset());

  // Scroll up and ensure the browser controls does not move until we recover
  // 100px previously scrolled.
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollUpdate, 0, 40.f));
  CompositeForTest();
  EXPECT_FLOAT_EQ(0.f, web_view->GetBrowserControls().ContentOffset());
  EXPECT_EQ(ScrollOffset(0, 160),
            GetFrame()->View()->LayoutViewport()->GetScrollOffset());

  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollUpdate, 0, 60.f));
  CompositeForTest();
  EXPECT_FLOAT_EQ(0.f, web_view->GetBrowserControls().ContentOffset());
  EXPECT_EQ(ScrollOffset(0, 100),
            GetFrame()->View()->LayoutViewport()->GetScrollOffset());

  // Now we have hit the threshold so further scroll up should be consumed by
  // browser controls.
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollUpdate, 0, 30.f));
  CompositeForTest();
  EXPECT_FLOAT_EQ(30.f, web_view->GetBrowserControls().ContentOffset());
  EXPECT_EQ(ScrollOffset(0, 100),
            GetFrame()->View()->LayoutViewport()->GetScrollOffset());

  // Once top control is fully shown then page should consume any excess scroll.
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollUpdate, 0, 70.f));
  CompositeForTest();
  EXPECT_FLOAT_EQ(50.f, web_view->GetBrowserControls().ContentOffset());
  EXPECT_EQ(ScrollOffset(0, 50),
            GetFrame()->View()->LayoutViewport()->GetScrollOffset());
}

// Scrolling down should always cause visible browser controls to start hiding
// even if we have been scrolling up previously.
TEST_F(BrowserControlsTest, MAYBE(ScrollUpThenDown)) {
  WebViewImpl* web_view = Initialize();
  // initialize browser controls to be hidden and position page at 100px.
  web_view->ResizeWithBrowserControls(web_view->MainFrameViewWidget()->Size(),
                                      50.f, 0, false);
  web_view->GetBrowserControls().SetShownRatio(0, 0);
  GetFrame()->View()->GetScrollableArea()->SetScrollOffset(
      ScrollOffset(0, 100), mojom::blink::ScrollType::kProgrammatic);
  CompositeForTest();

  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollBegin));
  EXPECT_FLOAT_EQ(0.f, web_view->GetBrowserControls().ContentOffset());

  // Scroll up to completely show browser controls. Excess deltaY (50px) should
  // be consumed by the page.
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollUpdate, 0, 100.f));
  CompositeForTest();
  EXPECT_FLOAT_EQ(50.f, web_view->GetBrowserControls().ContentOffset());
  EXPECT_EQ(ScrollOffset(0, 50),
            GetFrame()->View()->LayoutViewport()->GetScrollOffset());

  // Scroll down and ensure only browser controls is scrolled
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollUpdate, 0, -40.f));
  CompositeForTest();
  EXPECT_FLOAT_EQ(10.f, web_view->GetBrowserControls().ContentOffset());
  EXPECT_EQ(ScrollOffset(0, 50),
            GetFrame()->View()->LayoutViewport()->GetScrollOffset());

  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollUpdate, 0, -60.f));
  CompositeForTest();
  EXPECT_FLOAT_EQ(0.f, web_view->GetBrowserControls().ContentOffset());
  EXPECT_EQ(ScrollOffset(0, 100),
            GetFrame()->View()->LayoutViewport()->GetScrollOffset());
}

// Browser controls should not consume horizontal scroll.
TEST_F(BrowserControlsTest, MAYBE(HorizontalScroll)) {
  WebViewImpl* web_view = Initialize();
  // initialize browser controls to be shown.
  web_view->ResizeWithBrowserControls(web_view->MainFrameViewWidget()->Size(),
                                      50.f, 0, true);
  web_view->GetBrowserControls().SetShownRatio(1, 1);
  CompositeForTest();

  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollBegin));
  EXPECT_FLOAT_EQ(50.f, web_view->GetBrowserControls().ContentOffset());

  // Browser controls should not consume horizontal scroll.
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollUpdate, -110.f, -100.f));
  CompositeForTest();
  EXPECT_FLOAT_EQ(0.f, web_view->GetBrowserControls().ContentOffset());
  EXPECT_EQ(ScrollOffset(110, 50),
            GetFrame()->View()->LayoutViewport()->GetScrollOffset());

  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollUpdate, -40.f, 0));
  CompositeForTest();
  EXPECT_FLOAT_EQ(0.f, web_view->GetBrowserControls().ContentOffset());
  EXPECT_EQ(ScrollOffset(150, 50),
            GetFrame()->View()->LayoutViewport()->GetScrollOffset());
}

// Page scale should not impact browser controls scrolling
TEST_F(BrowserControlsTest, MAYBE(PageScaleHasNoImpact)) {
  WebViewImpl* web_view = Initialize();
  GetWebView()->SetDefaultPageScaleLimits(0.25f, 5);
  web_view->SetPageScaleFactor(2.0);

  // Initialize browser controls to be shown.
  web_view->ResizeWithBrowserControls(web_view->MainFrameViewWidget()->Size(),
                                      50.f, 0, true);
  web_view->GetBrowserControls().SetShownRatio(1, 1);
  CompositeForTest();

  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollBegin));
  EXPECT_FLOAT_EQ(50.f, web_view->GetBrowserControls().ContentOffset());

  // Browser controls should be scrolled partially and page should not scroll.
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollUpdate, 0, -20.f));
  CompositeForTest();
  EXPECT_FLOAT_EQ(30.f, web_view->GetBrowserControls().ContentOffset());
  EXPECT_EQ(ScrollOffset(0, 0),
            GetFrame()->View()->GetScrollableArea()->GetScrollOffset());

  // Browser controls should consume 30px and become hidden. Excess scroll
  // should be consumed by the page at 2x scale.
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollUpdate, 0, -70.f));
  CompositeForTest();
  EXPECT_FLOAT_EQ(0.f, web_view->GetBrowserControls().ContentOffset());
  EXPECT_EQ(ScrollOffset(0, 20),
            GetFrame()->View()->GetScrollableArea()->GetScrollOffset());

  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollEnd));

  // Change page scale and test.
  web_view->SetPageScaleFactor(0.5);
  CompositeForTest();

  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputE
"""


```