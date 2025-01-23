Response:
The user wants a summary of the provided C++ code, which is a test file for scrollbar functionality within the Chromium Blink rendering engine. I need to identify the key functionalities being tested and explain their relation to web technologies like JavaScript, HTML, and CSS. I should also look for any explicit logic testing and common usage errors the tests might be preventing.

Here's a breakdown of the code's functionality:

1. **Setup and Teardown:**  Initializes and cleans up the testing environment, including handling overlay scrollbar settings.
2. **Event Handling:**  Simulates mouse events (move, press, release, etc.) to interact with scrollbars.
3. **Hit Testing:** Checks which element is under a given point, including scrollbar parts.
4. **Scrollbar Properties:**  Tests the existence, type (overlay or regular), and visibility of scrollbars.
5. **Custom Scrollbars:**  Focuses on testing custom scrollbar styling using CSS (`::-webkit-scrollbar`, etc.).
6. **Overlay Scrollbars:**  Specifically tests the behavior of overlay scrollbars, including their appearance and interaction.
7. **Theme Engine Interaction:** Uses a stub theme engine to control how scrollbars are painted and sized.
8. **Cursor Behavior:** Tests how the mouse cursor changes when hovering over different parts of the scrollbar.
9. **Layout and Rendering:** Checks if scrollbar changes trigger layout recalculations and affect rendering.
10. **Color Scheme:**  Verifies how the overlay scrollbar color scheme adapts to the page's background.

Now, I can structure the response based on the user's requirements.
这是对 `blink/renderer/core/layout/scrollbars_test.cc` 文件的功能归纳：

**核心功能:**

这个 C++ 文件包含了对 Chromium Blink 引擎中**滚动条 (scrollbars)** 功能进行测试的单元测试。主要目的是验证滚动条在各种场景下的行为是否符合预期。

**与 JavaScript, HTML, CSS 的关系及举例:**

这个测试文件直接关联到 web 开发中常用的 HTML, CSS 以及 JavaScript 对滚动条的控制和样式化：

1. **HTML (结构):**  测试会创建包含可滚动内容的 HTML 结构 (例如，通过设置 `overflow: scroll` 或内容超出容器尺寸)。
    *   **举例:**  测试中会创建带有 `overflow: scroll` 属性的 `<div>` 元素，以此来触发滚动条的显示。
    *   **假设输入:**  HTML 包含一个高度超出其容器的 `<div>` 元素。
    *   **预期输出:**  垂直滚动条应该出现。

2. **CSS (样式):**  测试会验证 CSS 样式对滚动条外观和行为的影响，包括自定义滚动条样式 (`::-webkit-scrollbar`) 以及控制滚动条的显示 (`display: none`).
    *   **举例:**  测试会检查通过 CSS 设置 `::-webkit-scrollbar { display: none; }` 后，滚动条是否被正确隐藏。
    *   **假设输入:**  CSS 规则中定义了 `::-webkit-scrollbar { display: none; }`。
    *   **预期输出:**  元素的滚动条应该不显示。
    *   **举例:**  测试还会验证自定义滚动条的尺寸和颜色是否生效。
    *   **假设输入:**  CSS 规则中定义了 `::-webkit-scrollbar { width: 10px; background-color: red; }`。
    *   **预期输出:**  滚动条的宽度应为 10 像素，背景颜色应为红色。

3. **JavaScript (交互):** 测试会模拟用户的交互行为 (例如鼠标移动、点击) 来测试滚动条的响应，以及通过 JavaScript 修改样式来观察滚动条的变化。
    *   **举例:**  测试会模拟鼠标移动到滚动条上，并检查鼠标指针的样式是否正确 (例如，变成 `pointer` 或自定义的 `cursor` 值)。
    *   **假设输入:**  鼠标指针移动到滚动条的滑块区域。
    *   **预期输出:**  鼠标指针应该变成指示可拖动的样式。
    *   **举例:**  测试会通过 JavaScript 动态修改元素的 CSS 样式，观察滚动条的显示/隐藏或样式变化。
    *   **假设输入:**  JavaScript 代码将元素的 `overflow` 属性从 `auto` 修改为 `hidden`。
    *   **预期输出:**  如果之前有滚动条，则滚动条应该被隐藏。

**逻辑推理的假设输入与输出:**

*   **假设输入:**  设置一个元素的 `overflow: scroll`，并且其内容高度大于容器高度。
*   **预期输出:**  垂直滚动条会出现。
*   **假设输入:**  在一个可滚动的元素上，鼠标移动到垂直滚动条的滑块区域。
*   **预期输出:**  `HitTestResult` 会指示命中了一个滚动条部件 (`GetScrollbar()` 返回 true)。
*   **假设输入:**  通过 JavaScript 将一个包含滚动条的元素的类名修改为应用了 `::-webkit-scrollbar { display: none; }` 样式的类名。
*   **预期输出:**  该元素的滚动条会消失。

**用户或编程常见的使用错误举例:**

这个测试文件通过自动化测试来预防一些用户或开发者在使用滚动条时可能遇到的问题：

*   **自定义滚动条样式失效:**  测试确保了 CSS 自定义滚动条的样式规则 (`::-webkit-scrollbar`, `::-webkit-scrollbar-thumb` 等) 能够正确应用。如果开发者定义的样式没有生效，测试将会失败，从而提醒开发者检查 CSS 规则的正确性。
*   **overlay 滚动条显示异常:** 测试验证了 overlay 滚动条在各种情况下的显示和隐藏逻辑，例如，当内容没有溢出时，overlay 滚动条不应该显示。开发者可能会错误地认为设置 `overflow: scroll` 就一定会显示滚动条，而测试可以帮助纠正这种理解。
*   **动态修改样式导致滚动条状态错误:** 测试会模拟动态修改元素样式 (例如通过 JavaScript) 的场景，确保滚动条的状态 (显示/隐藏、类型) 能够正确更新。开发者在编写动态交互代码时可能会忽略样式修改对滚动条的影响，测试可以帮助发现这类问题。
*   **鼠标事件在滚动条上的处理不正确:** 测试模拟鼠标在滚动条上的移动和点击，验证事件是否被正确捕获和处理，以及鼠标指针样式是否符合预期。例如，开发者可能没有考虑到在自定义滚动条上设置特定的 `cursor` 样式。

**功能归纳:**

总而言之，`blink/renderer/core/layout/scrollbars_test.cc`  的主要功能是**全面测试 Blink 引擎中滚动条的各种特性和行为**，包括标准滚动条和 overlay 滚动条，以及它们与 HTML 结构、CSS 样式和 JavaScript 交互的正确性。它通过模拟各种场景和用户交互，确保滚动条功能的稳定性和可靠性，并帮助预防常见的开发错误。

### 提示词
```
这是目录为blink/renderer/core/layout/scrollbars_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/test/scoped_feature_list.h"
#include "build/build_config.h"
#include "cc/base/features.h"
#include "cc/paint/record_paint_canvas.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/input/web_coalesced_input_event.h"
#include "third_party/blink/public/common/input/web_pointer_properties.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/public/platform/web_theme_engine.h"
#include "third_party/blink/public/web/web_script_source.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/html/html_iframe_element.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/inspector/dev_tools_emulator.h"
#include "third_party/blink/renderer/core/layout/custom_scrollbar.h"
#include "third_party/blink/renderer/core/layout/layout_custom_scrollbar_part.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/scroll/scroll_types.h"
#include "third_party/blink/renderer/core/scroll/scrollbar_theme_overlay_mock.h"
#include "third_party/blink/renderer/core/testing/color_scheme_helper.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/testing/paint_test_configurations.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/url_test_helpers.h"
#include "third_party/blink/renderer/platform/theme/web_theme_engine_helper.h"
#include "ui/base/cursor/cursor.h"
#include "ui/base/cursor/mojom/cursor_type.mojom-blink.h"

namespace blink {

namespace {

class StubWebThemeEngine : public WebThemeEngine {
 public:
  StubWebThemeEngine() {
    painted_color_scheme_.fill(mojom::blink::ColorScheme::kLight);
  }

  gfx::Size GetSize(Part part) override {
    switch (part) {
      case kPartScrollbarHorizontalThumb:
        return gfx::Size(kMinimumHorizontalLength, 15);
      case kPartScrollbarVerticalThumb:
        return gfx::Size(15, kMinimumVerticalLength);
      default:
        return gfx::Size();
    }
  }
  static constexpr int kMinimumHorizontalLength = 51;
  static constexpr int kMinimumVerticalLength = 52;

  void Paint(cc::PaintCanvas*,
             Part part,
             State,
             const gfx::Rect&,
             const ExtraParams*,
             mojom::blink::ColorScheme color_scheme,
             bool in_forced_colors,
             const ui::ColorProvider* color_provider,
             const std::optional<SkColor>& accent_color) override {
    // Make  sure we don't overflow the array.
    DCHECK(part <= kPartProgressBar);
    painted_color_scheme_[part] = color_scheme;
  }

  mojom::blink::ColorScheme GetPaintedPartColorScheme(Part part) const {
    return painted_color_scheme_[part];
  }

  SkColor4f GetScrollbarThumbColor(State,
                                   const ExtraParams*,
                                   const ui::ColorProvider*) const override {
    return SkColors::kRed;
  }

 private:
  std::array<mojom::blink::ColorScheme, kPartProgressBar + 1>
      painted_color_scheme_;
};

constexpr int StubWebThemeEngine::kMinimumHorizontalLength;
constexpr int StubWebThemeEngine::kMinimumVerticalLength;

class ScopedStubThemeEngine {
 public:
  ScopedStubThemeEngine() {
    old_theme_ = WebThemeEngineHelper::SwapNativeThemeEngineForTesting(
        std::make_unique<StubWebThemeEngine>());
  }

  ~ScopedStubThemeEngine() {
    WebThemeEngineHelper::SwapNativeThemeEngineForTesting(
        std::move(old_theme_));
  }

 private:
  std::unique_ptr<WebThemeEngine> old_theme_;
};

}  // namespace

class ScrollbarsTest : public PaintTestConfigurations, public SimTest {
 public:
  void SetUp() override {
    SimTest::SetUp();
    // We don't use the mock scrollbar theme in this file, but use the normal
    // scrollbar theme with mock WebThemeEngine, for better control of testing
    // environment. This is after SimTest::SetUp() to override the mock overlay
    // scrollbar settings initialized there.
    mock_overlay_scrollbars_ =
        std::make_unique<ScopedMockOverlayScrollbars>(false);
    original_overlay_scrollbars_enabled_ =
        ScrollbarThemeSettings::OverlayScrollbarsEnabled();
  }

  void TearDown() override {
    SetOverlayScrollbarsEnabled(original_overlay_scrollbars_enabled_);
    mock_overlay_scrollbars_.reset();
    SimTest::TearDown();
  }

  void SetOverlayScrollbarsEnabled(bool enabled) {
    if (enabled != ScrollbarThemeSettings::OverlayScrollbarsEnabled()) {
      ScrollbarThemeSettings::SetOverlayScrollbarsEnabled(enabled);
      Page::UsesOverlayScrollbarsChanged();
    }
  }

  HitTestResult HitTest(int x, int y) {
    return WebView().MainFrameViewWidget()->CoreHitTestResultAt(
        gfx::PointF(x, y));
  }

  EventHandler& GetEventHandler() {
    return GetDocument().GetFrame()->GetEventHandler();
  }

  void HandleMouseMoveEvent(int x, int y) {
    WebMouseEvent event(WebInputEvent::Type::kMouseMove, gfx::PointF(x, y),
                        gfx::PointF(x, y),
                        WebPointerProperties::Button::kNoButton, 0,
                        WebInputEvent::kNoModifiers, base::TimeTicks::Now());
    event.SetFrameScale(1);
    GetEventHandler().HandleMouseMoveEvent(event, Vector<WebMouseEvent>(),
                                           Vector<WebMouseEvent>());
  }

  void HandleMousePressEvent(int x,
                             int y,
                             WebPointerProperties::Button button =
                                 WebPointerProperties::Button::kLeft) {
    WebMouseEvent event(WebInputEvent::Type::kMouseDown, gfx::PointF(x, y),
                        gfx::PointF(x, y), button, 0,
                        WebInputEvent::Modifiers::kLeftButtonDown,
                        base::TimeTicks::Now());
    event.SetFrameScale(1);
    GetEventHandler().HandleMousePressEvent(event);
  }

  void HandleContextMenuEvent(int x, int y) {
    WebMouseEvent event(
        WebInputEvent::Type::kMouseDown, gfx::PointF(x, y), gfx::PointF(x, y),
        WebPointerProperties::Button::kNoButton, 0,
        WebInputEvent::Modifiers::kNoModifiers, base::TimeTicks::Now());
    event.SetFrameScale(1);
    GetEventHandler().SendContextMenuEvent(event);
  }

  void HandleMouseReleaseEvent(int x,
                               int y,
                               WebPointerProperties::Button button =
                                   WebPointerProperties::Button::kLeft) {
    WebMouseEvent event(WebInputEvent::Type::kMouseUp, gfx::PointF(x, y),
                        gfx::PointF(x, y), button, 0,
                        WebInputEvent::Modifiers::kNoModifiers,
                        base::TimeTicks::Now());
    event.SetFrameScale(1);
    GetEventHandler().HandleMouseReleaseEvent(event);
  }

  void HandleMouseMiddlePressEvent(int x, int y) {
    WebMouseEvent event(
        WebInputEvent::Type::kMouseDown, gfx::PointF(x, y), gfx::PointF(x, y),
        WebPointerProperties::Button::kMiddle, 0,
        WebInputEvent::Modifiers::kMiddleButtonDown, base::TimeTicks::Now());
    event.SetFrameScale(1);
    GetEventHandler().HandleMousePressEvent(event);
  }

  void HandleMouseMiddleReleaseEvent(int x, int y) {
    WebMouseEvent event(
        WebInputEvent::Type::kMouseUp, gfx::PointF(x, y), gfx::PointF(x, y),
        WebPointerProperties::Button::kMiddle, 0,
        WebInputEvent::Modifiers::kMiddleButtonDown, base::TimeTicks::Now());
    event.SetFrameScale(1);
    GetEventHandler().HandleMouseReleaseEvent(event);
  }

  void HandleMouseLeaveEvent() {
    WebMouseEvent event(WebInputEvent::Type::kMouseLeave, gfx::PointF(1, 1),
                        gfx::PointF(1, 1), WebPointerProperties::Button::kLeft,
                        0, WebInputEvent::Modifiers::kLeftButtonDown,
                        base::TimeTicks::Now());
    event.SetFrameScale(1);
    GetEventHandler().HandleMouseLeaveEvent(event);
  }

  WebGestureEvent GenerateWheelGestureEvent(
      WebInputEvent::Type type,
      const gfx::Point& position,
      ScrollOffset offset = ScrollOffset()) {
    return GenerateGestureEvent(type, WebGestureDevice::kTouchpad, position,
                                offset);
  }

  WebCoalescedInputEvent GenerateTouchGestureEvent(
      WebInputEvent::Type type,
      const gfx::Point& position,
      ScrollOffset offset = ScrollOffset()) {
    return WebCoalescedInputEvent(
        GenerateGestureEvent(type, WebGestureDevice::kTouchscreen, position,
                             offset),
        ui::LatencyInfo());
  }

  ui::mojom::blink::CursorType CursorType() {
    return GetDocument()
        .GetFrame()
        ->GetChromeClient()
        .LastSetCursorForTesting()
        .type();
  }

  ScrollbarTheme& GetScrollbarTheme() {
    return GetDocument().GetPage()->GetScrollbarTheme();
  }

  PaintLayerScrollableArea* GetScrollableArea(const Element& element) const {
    return element.GetLayoutBox()->GetScrollableArea();
  }

 protected:
  WebGestureEvent GenerateGestureEvent(WebInputEvent::Type type,
                                       WebGestureDevice device,
                                       const gfx::Point& position,
                                       ScrollOffset offset) {
    WebGestureEvent event(type, WebInputEvent::kNoModifiers,
                          base::TimeTicks::Now(), device);

    event.SetPositionInWidget(gfx::PointF(position.x(), position.y()));

    if (type == WebInputEvent::Type::kGestureScrollUpdate) {
      event.data.scroll_update.delta_x = offset.x();
      event.data.scroll_update.delta_y = offset.y();
    } else if (type == WebInputEvent::Type::kGestureScrollBegin) {
      event.data.scroll_begin.delta_x_hint = offset.x();
      event.data.scroll_begin.delta_y_hint = offset.y();
    }
    return event;
  }

 private:
  ScopedStubThemeEngine scoped_theme_;
  std::unique_ptr<ScopedMockOverlayScrollbars> mock_overlay_scrollbars_;
  bool original_overlay_scrollbars_enabled_;
};

INSTANTIATE_PAINT_TEST_SUITE_P(ScrollbarsTest);

class ScrollbarsTestWithVirtualTimer : public ScrollbarsTest {
 public:
  void SetUp() override {
    ScrollbarsTest::SetUp();
    GetVirtualTimeController()->EnableVirtualTime(base::Time());
  }

  void TearDown() override {
    GetVirtualTimeController()->DisableVirtualTimeForTesting();
    ScrollbarsTest::TearDown();
  }

  void TimeAdvance() {
    GetVirtualTimeController()->SetVirtualTimePolicy(
        VirtualTimeController::VirtualTimePolicy::kAdvance);
  }

  void StopVirtualTimeAndExitRunLoop(base::OnceClosure quit_closure) {
    GetVirtualTimeController()->SetVirtualTimePolicy(
        VirtualTimeController::VirtualTimePolicy::kPause);
    std::move(quit_closure).Run();
  }

  // Some task queues may have repeating v8 tasks that run forever so we impose
  // a hard (virtual) time limit.
  void RunTasksForPeriod(base::TimeDelta delay) {
    base::RunLoop loop;
    TimeAdvance();
    scheduler::GetSingleThreadTaskRunnerForTesting()->PostDelayedTask(
        FROM_HERE,
        WTF::BindOnce(
            &ScrollbarsTestWithVirtualTimer::StopVirtualTimeAndExitRunLoop,
            WTF::Unretained(this), loop.QuitClosure()),
        delay);
    loop.Run();
  }

  VirtualTimeController* GetVirtualTimeController() {
    return WebView().Scheduler()->GetVirtualTimeController();
  }
};

INSTANTIATE_PAINT_TEST_SUITE_P(ScrollbarsTestWithVirtualTimer);

// Try to force enable/disable overlay. Skip the test if the desired setting
// is not supported by the platform.
#define ENABLE_OVERLAY_SCROLLBARS(b)                                           \
  do {                                                                         \
    SetOverlayScrollbarsEnabled(b);                                            \
    if (WebView().GetPage()->GetScrollbarTheme().UsesOverlayScrollbars() != b) \
      return;                                                                  \
  } while (false)

TEST_P(ScrollbarsTest, DocumentStyleRecalcPreservesScrollbars) {
  v8::HandleScope handle_scope(
      WebView().GetPage()->GetAgentGroupScheduler().Isolate());
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style> body { width: 1600px; height: 1200px; } </style>)HTML");
  auto* layout_viewport = GetDocument().View()->LayoutViewport();

  Compositor().BeginFrame();
  ASSERT_TRUE(layout_viewport->VerticalScrollbar() &&
              layout_viewport->HorizontalScrollbar());

  // Forces recalc of LayoutView's computed style in Document::updateStyle,
  // without invalidating layout.
  MainFrame().ExecuteScriptAndReturnValue(WebScriptSource(
      "document.querySelector('style').sheet.insertRule('body {}', 1);"));

  Compositor().BeginFrame();
  ASSERT_TRUE(layout_viewport->VerticalScrollbar() &&
              layout_viewport->HorizontalScrollbar());
}

TEST_P(ScrollbarsTest, ScrollbarsUpdatedOnOverlaySettingsChange) {
  ENABLE_OVERLAY_SCROLLBARS(true);

  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style> body { height: 3000px; } </style>)HTML");

  Compositor().BeginFrame();
  auto* layout_viewport = GetDocument().View()->LayoutViewport();
  EXPECT_TRUE(layout_viewport->VerticalScrollbar()->IsOverlayScrollbar());

  ENABLE_OVERLAY_SCROLLBARS(false);
  Compositor().BeginFrame();
  EXPECT_FALSE(layout_viewport->VerticalScrollbar()->IsOverlayScrollbar());
}

TEST(ScrollbarsTestWithOwnWebViewHelper, ScrollbarSizeF) {
  test::TaskEnvironment task_environment;
  ScopedTestingPlatformSupport<TestingPlatformSupport> platform;
  frame_test_helpers::WebViewHelper web_view_helper;
  // Needed so visual viewport supplies its own scrollbars. We don't support
  // this setting changing after initialization, so we must set it through
  // WebViewHelper.
  web_view_helper.set_viewport_enabled(true);

  WebViewImpl* web_view_impl = web_view_helper.Initialize();

  web_view_impl->MainFrameViewWidget()->SetDeviceScaleFactorForTesting(1.f);
  web_view_impl->MainFrameViewWidget()->Resize(gfx::Size(800, 600));

  WebURL base_url = url_test_helpers::ToKURL("http://example.com/");
  frame_test_helpers::LoadHTMLString(web_view_impl->MainFrameImpl(),
                                     "<!DOCTYPE html>"
                                     "<style>"
                                     "  body {"
                                     "    width: 1600px;"
                                     "    height: 1200px;"
                                     "  }"
                                     "</style>"
                                     "<body>"
                                     "</body>",
                                     base_url);
  web_view_impl->MainFrameViewWidget()->UpdateAllLifecyclePhases(
      DocumentUpdateReason::kTest);

  Document* document =
      To<LocalFrame>(web_view_impl->GetPage()->MainFrame())->GetDocument();

  VisualViewport& visual_viewport = document->GetPage()->GetVisualViewport();
  int horizontal_scrollbar =
      visual_viewport.LayerForHorizontalScrollbar()->bounds().height();
  int vertical_scrollbar =
      visual_viewport.LayerForVerticalScrollbar()->bounds().width();

  const float device_scale = 3.5f;
  web_view_impl->MainFrameViewWidget()->SetDeviceScaleFactorForTesting(
      device_scale);
  web_view_impl->MainFrameViewWidget()->Resize(gfx::Size(400, 300));

  EXPECT_EQ(ClampTo<int>(std::floor(horizontal_scrollbar * device_scale)),
            visual_viewport.LayerForHorizontalScrollbar()->bounds().height());
  EXPECT_EQ(ClampTo<int>(std::floor(vertical_scrollbar * device_scale)),
            visual_viewport.LayerForVerticalScrollbar()->bounds().width());

  web_view_impl->MainFrameViewWidget()->SetDeviceScaleFactorForTesting(1.f);
  web_view_impl->MainFrameViewWidget()->Resize(gfx::Size(800, 600));

  EXPECT_EQ(horizontal_scrollbar,
            visual_viewport.LayerForHorizontalScrollbar()->bounds().height());
  EXPECT_EQ(vertical_scrollbar,
            visual_viewport.LayerForVerticalScrollbar()->bounds().width());
}

// Ensure that causing a change in scrollbar existence causes a nested layout
// to recalculate the existence of the opposite scrollbar. The bug here was
// caused by trying to avoid the layout when overlays are enabled but not
// checking whether the scrollbars should be custom - which do take up layout
// space. https://crbug.com/668387.
TEST_P(ScrollbarsTest, CustomScrollbarsCauseLayoutOnExistenceChange) {
  // This test is specifically checking the behavior when overlay scrollbars
  // are enabled.
  ENABLE_OVERLAY_SCROLLBARS(true);

  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      ::-webkit-scrollbar {
          height: 16px;
          width: 16px
      }
      ::-webkit-scrollbar-thumb {
          background-color: rgba(0,0,0,.2);
      }
      html, body{
        margin: 0;
        height: 100%;
      }
      .box {
        width: 100%;
        height: 100%;
      }
      .transformed {
        transform: translateY(100px);
      }
    </style>
    <div id='box' class='box'></div>
  )HTML");

  ScrollableArea* layout_viewport = GetDocument().View()->LayoutViewport();

  Compositor().BeginFrame();

  ASSERT_FALSE(layout_viewport->VerticalScrollbar());
  ASSERT_FALSE(layout_viewport->HorizontalScrollbar());

  // Adding translation will cause a vertical scrollbar to appear but not dirty
  // layout otherwise. Ensure the change of scrollbar causes a layout to
  // recalculate the page width with the vertical scrollbar added.
  MainFrame().ExecuteScript(WebScriptSource(
      "document.getElementById('box').className = 'box transformed';"));
  Compositor().BeginFrame();

  ASSERT_TRUE(layout_viewport->VerticalScrollbar());
  ASSERT_FALSE(layout_viewport->HorizontalScrollbar());
}

TEST_P(ScrollbarsTest, TransparentBackgroundUsesLightOverlayColorScheme) {
  // This test is specifically checking the behavior when overlay scrollbars
  // are enabled.
  ENABLE_OVERLAY_SCROLLBARS(true);

  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  WebView().SetPageBaseBackgroundColor(SK_ColorTRANSPARENT);
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body{
        height: 300%;
      }
    </style>
  )HTML");
  Compositor().BeginFrame();

  ScrollableArea* layout_viewport = GetDocument().View()->LayoutViewport();

  EXPECT_EQ(mojom::blink::ColorScheme::kLight,
            layout_viewport->GetOverlayScrollbarColorScheme());
}

TEST_P(ScrollbarsTest, BodyBackgroundChangesOverlayColorTheme) {
  // This test is specifically checking the behavior when overlay scrollbars
  // are enabled.
  ENABLE_OVERLAY_SCROLLBARS(true);

  v8::HandleScope handle_scope(
      WebView().GetPage()->GetAgentGroupScheduler().Isolate());
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <body style='background:white'></body>
  )HTML");
  Compositor().BeginFrame();

  ScrollableArea* layout_viewport = GetDocument().View()->LayoutViewport();

  EXPECT_EQ(mojom::blink::ColorScheme::kLight,
            layout_viewport->GetOverlayScrollbarColorScheme());

  MainFrame().ExecuteScriptAndReturnValue(
      WebScriptSource("document.body.style.backgroundColor = 'black';"));

  Compositor().BeginFrame();
  EXPECT_EQ(mojom::blink::ColorScheme::kDark,
            layout_viewport->GetOverlayScrollbarColorScheme());
}

// Ensure overlay scrollbar change to display:none correctly.
TEST_P(ScrollbarsTest, OverlayScrollbarChangeToDisplayNoneDynamically) {
  // This test is specifically checking the behavior when overlay scrollbars
  // are enabled.
  ENABLE_OVERLAY_SCROLLBARS(true);

  WebView().MainFrameViewWidget()->Resize(gfx::Size(200, 200));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
    .noscrollbars::-webkit-scrollbar { display: none; }
    #div{ height: 100px; width:100px; overflow:scroll; }
    .big{ height: 2000px; }
    body { overflow:scroll; }
    </style>
    <div id='div'>
      <div class='big'>
      </div>
    </div>
    <div class='big'>
    </div>
  )HTML");
  Compositor().BeginFrame();

  Document& document = GetDocument();
  Element* div = document.getElementById(AtomicString("div"));

  // Ensure we have overlay scrollbar for div and root.
  auto* scrollable_div = GetScrollableArea(*div);

  ScrollableArea* scrollable_root = GetDocument().View()->LayoutViewport();

  DCHECK(scrollable_div->VerticalScrollbar());
  DCHECK(scrollable_div->VerticalScrollbar()->IsOverlayScrollbar());

  DCHECK(!scrollable_div->HorizontalScrollbar());

  DCHECK(scrollable_root->VerticalScrollbar());
  DCHECK(scrollable_root->VerticalScrollbar()->IsOverlayScrollbar());

  // For PaintLayer Overlay Scrollbar we will remove the scrollbar when it is
  // not necessary even with overflow:scroll.
  DCHECK(!scrollable_root->HorizontalScrollbar());

  // Set display:none.
  div->setAttribute(html_names::kClassAttr, AtomicString("noscrollbars"));
  document.body()->setAttribute(html_names::kClassAttr,
                                AtomicString("noscrollbars"));
  Compositor().BeginFrame();

  EXPECT_TRUE(scrollable_div->VerticalScrollbar());
  EXPECT_TRUE(scrollable_div->VerticalScrollbar()->IsCustomScrollbar());
  EXPECT_TRUE(scrollable_div->VerticalScrollbar()->FrameRect().IsEmpty());

  EXPECT_TRUE(scrollable_div->HorizontalScrollbar());
  EXPECT_TRUE(scrollable_div->HorizontalScrollbar()->IsCustomScrollbar());
  EXPECT_TRUE(scrollable_div->HorizontalScrollbar()->FrameRect().IsEmpty());

  EXPECT_TRUE(scrollable_root->VerticalScrollbar());
  EXPECT_TRUE(scrollable_root->VerticalScrollbar()->IsCustomScrollbar());
  EXPECT_TRUE(scrollable_root->VerticalScrollbar()->FrameRect().IsEmpty());

  EXPECT_TRUE(scrollable_root->HorizontalScrollbar());
  EXPECT_TRUE(scrollable_root->HorizontalScrollbar()->IsCustomScrollbar());
  EXPECT_TRUE(scrollable_root->HorizontalScrollbar()->FrameRect().IsEmpty());
}

// Ensure that overlay scrollbars are not created, even in overflow:scroll,
// situations when there's no overflow. Specifically, after style-only changes.
TEST_P(ScrollbarsTest, OverlayScrolblarNotCreatedInUnscrollableAxis) {
  // This test is specifically checking the behavior when overlay scrollbars
  // are enabled.
  ENABLE_OVERLAY_SCROLLBARS(true);

  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      #target {
        width: 100px;
        height: 100px;
        overflow-y: scroll;
        opacity: 0.5;
      }
    </style>
    <div id="target"></div>
  )HTML");

  Compositor().BeginFrame();

  auto* target = GetDocument().getElementById(AtomicString("target"));
  auto* scrollable_area = target->GetLayoutBox()->GetScrollableArea();

  ASSERT_FALSE(scrollable_area->VerticalScrollbar());
  ASSERT_FALSE(scrollable_area->HorizontalScrollbar());

  // Mutate the opacity so that we cause a style-only change.
  target->setAttribute(html_names::kStyleAttr, AtomicString("opacity: 0.9"));
  Compositor().BeginFrame();

  ASSERT_FALSE(scrollable_area->VerticalScrollbar());
  ASSERT_FALSE(scrollable_area->HorizontalScrollbar());
}

TEST_P(ScrollbarsTest, HidingScrollbarsOnScrollableAreaDisablesScrollbars) {
  // This test is specifically checking the behavior when overlay scrollbars
  // are enabled.
  ENABLE_OVERLAY_SCROLLBARS(true);

  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));

  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      #scroller { overflow: scroll; width: 1000px; height: 1000px }
      #spacer { width: 2000px; height: 2000px }
    </style>
    <div id='scroller'>
      <div id='spacer'></div>
    </div>
  )HTML");
  Compositor().BeginFrame();

  Document& document = GetDocument();
  LocalFrameView* frame_view = WebView().MainFrameImpl()->GetFrameView();
  Element* scroller = document.getElementById(AtomicString("scroller"));
  auto* scroller_area = GetScrollableArea(*scroller);
  ScrollableArea* frame_scroller_area = frame_view->LayoutViewport();

  // Scrollbars are hidden at start.
  scroller_area->SetScrollbarsHiddenForTesting(true);
  frame_scroller_area->SetScrollbarsHiddenForTesting(true);
  ASSERT_TRUE(scroller_area->HorizontalScrollbar());
  ASSERT_TRUE(scroller_area->VerticalScrollbar());
  ASSERT_TRUE(frame_scroller_area->HorizontalScrollbar());
  ASSERT_TRUE(frame_scroller_area->VerticalScrollbar());

  EXPECT_TRUE(frame_scroller_area->ScrollbarsHiddenIfOverlay());
  EXPECT_FALSE(frame_scroller_area->HorizontalScrollbar()
                   ->ShouldParticipateInHitTesting());
  EXPECT_FALSE(frame_scroller_area->VerticalScrollbar()
                   ->ShouldParticipateInHitTesting());

  EXPECT_TRUE(scroller_area->ScrollbarsHiddenIfOverlay());
  EXPECT_FALSE(
      scroller_area->HorizontalScrollbar()->ShouldParticipateInHitTesting());
  EXPECT_FALSE(
      scroller_area->VerticalScrollbar()->ShouldParticipateInHitTesting());

  frame_scroller_area->SetScrollbarsHiddenForTesting(false);
  EXPECT_TRUE(frame_scroller_area->HorizontalScrollbar()
                  ->ShouldParticipateInHitTesting());
  EXPECT_TRUE(frame_scroller_area->VerticalScrollbar()
                  ->ShouldParticipateInHitTesting());
  frame_scroller_area->SetScrollbarsHiddenForTesting(true);
  EXPECT_FALSE(frame_scroller_area->HorizontalScrollbar()
                   ->ShouldParticipateInHitTesting());
  EXPECT_FALSE(frame_scroller_area->VerticalScrollbar()
                   ->ShouldParticipateInHitTesting());

  scroller_area->SetScrollbarsHiddenForTesting(false);
  EXPECT_TRUE(
      scroller_area->HorizontalScrollbar()->ShouldParticipateInHitTesting());
  EXPECT_TRUE(
      scroller_area->VerticalScrollbar()->ShouldParticipateInHitTesting());
  scroller_area->SetScrollbarsHiddenForTesting(true);
  EXPECT_FALSE(
      scroller_area->HorizontalScrollbar()->ShouldParticipateInHitTesting());
  EXPECT_FALSE(
      scroller_area->VerticalScrollbar()->ShouldParticipateInHitTesting());
}

// Ensure mouse cursor should be pointer when hovering over the scrollbar.
TEST_P(ScrollbarsTest, MouseOverScrollbarInCustomCursorElement) {
  // Skip this test if scrollbars don't allow hit testing on the platform.
  if (!WebView().GetPage()->GetScrollbarTheme().AllowsHitTest())
    return;

  WebView().MainFrameViewWidget()->Resize(gfx::Size(250, 250));

  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
    body {
      margin: 0;
    }
    #d1 {
      width: 200px;
      height: 200px;
      overflow: auto;
      cursor: move;
    }
    #d2 {
      height: 400px;
    }
    </style>
    <div id='d1'>
        <div id='d2'></div>
    </div>
  )HTML");
  Compositor().BeginFrame();

  Document& document = GetDocument();

  Element* div = document.getElementById(AtomicString("d1"));

  // Ensure hittest has DIV and scrollbar.
  HitTestResult hit_test_result = HitTest(195, 5);

  EXPECT_EQ(hit_test_result.InnerElement(), div);
  EXPECT_TRUE(hit_test_result.GetScrollbar());

  HandleMouseMoveEvent(195, 5);

  EXPECT_EQ(ui::mojom::blink::CursorType::kPointer, CursorType());
}

// Ensure mouse cursor should be override when hovering over the custom
// scrollbar.
TEST_P(ScrollbarsTest, MouseOverCustomScrollbarInCustomCursorElement) {
  // Skip this test if scrollbars don't allow hit testing on the platform.
  if (!WebView().GetPage()->GetScrollbarTheme().AllowsHitTest())
    return;

  WebView().MainFrameViewWidget()->Resize(gfx::Size(250, 250));

  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
    body {
      margin: 0;
    }
    #d1 {
      width: 200px;
      height: 200px;
      overflow: auto;
      cursor: move;
    }
    #d2 {
      height: 400px;
    }
    ::-webkit-scrollbar {
      background: none;
      height: 5px;
      width: 5px;
    }
    ::-webkit-scrollbar-thumb {
      background-color: black;
    }
    </style>
    <div id='d1'>
        <div id='d2'></div>
    </div>
  )HTML");
  Compositor().BeginFrame();

  Document& document = GetDocument();

  Element* div = document.getElementById(AtomicString("d1"));

  // Ensure hittest has DIV and scrollbar.
  HitTestResult hit_test_result = HitTest(195, 5);

  EXPECT_EQ(hit_test_result.InnerElement(), div);
  EXPECT_TRUE(hit_test_result.GetScrollbar());

  HandleMouseMoveEvent(195, 5);

  EXPECT_EQ(ui::mojom::blink::CursorType::kMove, CursorType());
}

// Ensure mouse cursor should be custom style when hovering over the custom
// scrollbar with custom cursor style.
TEST_P(ScrollbarsTest, MouseOverCustomScrollbarWithCustomCursor) {
  // Skip this test if scrollbars don't allow hit testing on the platform.
  if (!WebView().GetPage()->GetScrollbarTheme().AllowsHitTest()) {
    return;
  }

  WebView().MainFrameViewWidget()->Resize(gfx::Size(250, 250));

  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
    body {
      margin: 0;
    }
    #d1 {
      width: 200px;
      height: 200px;
      overflow: auto;
      cursor: move;
    }
    #d2 {
      height: 400px;
    }
    ::-webkit-scrollbar {
      background: none;
      height: 5px;
      width: 5px;
      cursor: pointer;
    }
    </style>
    <div id='d1'>
        <div id='d2'></div>
    </div>
  )HTML");
  Compositor().BeginFrame();

  Document& document = GetDocument();

  Element* div = document.getElementById(AtomicString("d1"));

  // Ensure hittest has DIV and scrollbar.
  HitTestResult hit_test_result = HitTest(195, 5);

  EXPECT_EQ(hit_test_result.InnerElement(), div);
  EXPECT_TRUE(hit_test_result.GetScrollbar());
  HandleMouseMoveEvent(195, 5);
  EXPECT_EQ(ui::mojom::blink::CursorType::kHand, CursorType());
}

// Ensure mouse cursor should be custom style when hovering over the custom
// scrollbar-thumb with custom cursor style.
TEST_P(ScrollbarsTest, MouseOverCustomScrollbarThumbWithCustomCursor) {
  // Skip this test if scrollbars don't allow hit testing on the platform.
  if (!WebView().GetPage()->GetScrollbarTheme().AllowsHitTest()) {
    return;
  }

  WebView().MainFrameViewWidget()->Resize(gfx::Size(250, 250));

  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
    body {
      margin: 0;
    }
    #d1 {
      width: 200px;
      height: 200px;
      overflow: auto;
      cursor: move;
    }
    #d2 {
      height: 400px;
    }
    ::-webkit-scrollbar {
      background: none;
```